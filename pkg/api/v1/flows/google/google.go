//SPDX-License-Identifier: Apache-2.0

package google

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/manager/flow"
)

type Google struct {
	logger  types.Logger
	options options.Options
}

// Request and Response types

type LoginInput struct {
	Next string `query:"next" required:"true" doc:"Redirect URL after authentication"`
	Code string `query:"code" maxLength:"8" doc:"Optional device flow code"`
}

type GoogleLoginHeaders struct {
	Location string `header:"Location" doc:"Redirect to Google OAuth"`
}

type LoginOutput struct {
	StatusCode int `json:"-" default:"307"`
	Headers    GoogleLoginHeaders
}

type CallbackInput struct {
	Code  string `query:"code" required:"true" doc:"OAuth authorization code"`
	State string `query:"state" required:"true" doc:"OAuth state parameter"`
}

type GoogleCallbackHeaders struct {
	SetCookie *http.Cookie `header:"Set-Cookie,omitempty" doc:"Session cookie"`
	Location  string       `header:"Location" doc:"Redirect to next URL"`
}

type CallbackOutput struct {
	StatusCode int `json:"-" default:"307"`
	Headers    GoogleCallbackHeaders
}

// RegisterEndpoints registers the Google OAuth endpoints with Huma
func RegisterEndpoints(api huma.API, options options.Options, logger types.Logger) {
	g := &Google{
		logger:  logger.SubLogger("GOOGLE"),
		options: options,
	}

	huma.Register(api, huma.Operation{
		OperationID: "google-login",
		Method:      "GET",
		Path:        "/flows/google/login",
		Summary:     "Initiate Google OAuth login",
		Description: "Redirects the user to Google for OAuth authentication",
		Tags:        []string{"google", "login"},
		Responses: map[string]*huma.Response{
			"307": {
				Description: "Redirect to Google OAuth",
				Headers: map[string]*huma.Param{
					"Location": {
						Description: "Google OAuth URL",
						Required:    true,
					},
				},
			},
		},
	}, g.login)

	huma.Register(api, huma.Operation{
		OperationID: "google-callback",
		Method:      "GET",
		Path:        "/flows/google/callback",
		Summary:     "Google OAuth callback",
		Description: "Handles the OAuth callback from Google and creates a session",
		Tags:        []string{"google", "callback"},
		Responses: map[string]*huma.Response{
			"307": {
				Description: "Redirect to application",
				Headers: map[string]*huma.Param{
					"Location": {
						Description: "Application redirect URL",
						Required:    true,
					},
					"Set-Cookie": {
						Description: "Session cookie (set for non-device flows)",
						Required:    false,
					},
				},
			},
		},
	}, g.callback)
}

// Handler implementations

func (g *Google) login(ctx context.Context, input *LoginInput) (*LoginOutput, error) {
	// Extract Fiber context for IP logging
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)
	g.logger.Debug().Str("IP", fiberCtx.IP()).Msg("login")

	if g.options.Manager.Google() == nil {
		return nil, huma.Error401Unauthorized("google provider is not enabled")
	}

	var err error
	var deviceIdentifier string

	if input.Code != "" && len(input.Code) == 8 {
		if g.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
		deviceIdentifier, err = g.options.Manager.Device().ExistsFlow(ctx, input.Code)
		if err != nil {
			g.logger.Error().Err(err).Msg("error checking if flow exists")
			return nil, huma.Error500InternalServerError("internal server error")
		}
		if deviceIdentifier == "" {
			return nil, huma.Error404NotFound("device flow does not exist")
		}
	}

	redirect, err := g.options.Manager.Google().CreateFlow(ctx, deviceIdentifier, "", input.Next)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to get redirect")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	return &LoginOutput{
		StatusCode: 307,
		Headers: GoogleLoginHeaders{
			Location: redirect,
		},
	}, nil
}

func (g *Google) callback(ctx context.Context, input *CallbackInput) (*CallbackOutput, error) {
	// Extract Fiber context for IP logging
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)
	g.logger.Debug().Str("IP", fiberCtx.IP()).Msg("callback")

	if g.options.Manager.Google() == nil {
		return nil, huma.Error401Unauthorized("google provider is not enabled")
	}

	f, err := g.options.Manager.Google().CompleteFlow(ctx, input.State, input.Code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, huma.Error404NotFound("flow does not exist")
		}
		g.logger.Error().Err(err).Msg("failed to complete flow")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	if f.DeviceIdentifier != "" {
		if g.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
	}

	session, err := g.options.Manager.CreateSession(ctx, f, flow.GoogleProvider)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to create session")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	output := &CallbackOutput{
		StatusCode: 307,
		Headers: GoogleCallbackHeaders{
			Location: f.NextURL,
		},
	}

	if f.DeviceIdentifier != "" {
		// Device flow - complete the device flow but don't set cookie
		err = g.options.Manager.Device().CompleteFlow(ctx, f.DeviceIdentifier, session.Identifier)
		if err != nil {
			g.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("internal server error")
		}
	} else {
		// Regular flow - set session cookie
		token, err := g.options.Manager.SignSession(session)
		if err != nil {
			g.logger.Error().Err(err).Msg("error signing session")
			return nil, huma.Error500InternalServerError("internal server error")
		}

		output.Headers.SetCookie = &http.Cookie{
			Name:     models.SessionCookie,
			Value:    token,
			Expires:  session.ExpiresAt,
			Domain:   g.options.Endpoint,
			Secure:   g.options.TLS,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
	}

	return output, nil
}
