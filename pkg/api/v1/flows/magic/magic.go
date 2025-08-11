//SPDX-License-Identifier: Apache-2.0

package magic

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"

	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/mailer"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
)

type Magic struct {
	logger        types.Logger
	emailVerifier *emailverifier.Verifier
	options       options.Options
}

// Request and Response types

type LoginInput struct {
	Email string `query:"email" required:"true" doc:"Email address"`
	Next  string `query:"next" required:"true" doc:"Redirect URL after authentication"`
	Code  string `query:"code" maxLength:"8" doc:"Optional device flow code"`
}

type LoginOutput struct {
	StatusCode int `json:"-" default:"200"`
}

type CallbackInput struct {
	Token string `query:"token" required:"true" doc:"Magic link token"`
}

type MagicCallbackHeaders struct {
	SetCookie *http.Cookie `header:"Set-Cookie,omitempty" doc:"Session cookie"`
	Location  string       `header:"Location" doc:"Redirect to next URL"`
}

type CallbackOutput struct {
	StatusCode int `json:"-" default:"307"`
	Headers    MagicCallbackHeaders
}

// RegisterEndpoints registers the Magic Link endpoints with Huma
func RegisterEndpoints(api huma.API, options options.Options, logger types.Logger) {
	m := &Magic{
		logger:        logger.SubLogger("MAGIC"),
		emailVerifier: emailverifier.NewVerifier(),
		options:       options,
	}

	huma.Register(api, huma.Operation{
		OperationID: "magic-login",
		Method:      "GET",
		Path:        "/flows/magic/login",
		Summary:     "Send magic link",
		Description: "Sends a magic link to the specified email address",
		Tags:        []string{"magic", "login"},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Magic link sent successfully",
			},
		},
	}, m.login)

	huma.Register(api, huma.Operation{
		OperationID: "magic-callback",
		Method:      "GET",
		Path:        "/flows/magic/callback",
		Summary:     "Magic link callback",
		Description: "Handles the magic link callback and creates a session",
		Tags:        []string{"magic", "callback"},
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
	}, m.callback)
}

// Handler implementations

func (m *Magic) login(ctx context.Context, input *LoginInput) (*LoginOutput, error) {
	// Extract Fiber context for IP logging
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)
	m.logger.Debug().Str("IP", fiberCtx.IP()).Msg("login")

	if m.options.Manager.Magic() == nil {
		return nil, huma.Error401Unauthorized("magic provider is not enabled")
	}

	if m.options.Manager.Mailer() == nil {
		return nil, huma.Error401Unauthorized("email provider is not enabled")
	}

	ret, err := m.emailVerifier.Verify(input.Email)
	if err != nil || !ret.Syntax.Valid || !ret.HasMxRecords {
		return nil, huma.Error400BadRequest("invalid email address")
	}

	var deviceIdentifier string
	if input.Code != "" && len(input.Code) == 8 {
		if m.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
		deviceIdentifier, err = m.options.Manager.Device().ExistsFlow(ctx, input.Code)
		if err != nil {
			m.logger.Error().Err(err).Msg("error checking if flow exists")
			return nil, huma.Error500InternalServerError("internal server error")
		}
		if deviceIdentifier == "" {
			return nil, huma.Error404NotFound("device flow does not exist")
		}
	}

	token, err := m.options.Manager.Magic().CreateFlow(ctx, input.Email, deviceIdentifier, "", input.Next)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to get token")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	var callback url.URL
	callback.Scheme = "http"
	if m.options.TLS {
		callback.Scheme = "https"
	}
	callback.Host = m.options.Endpoint
	callback.Path = "/v1/flows/magic/callback"
	q := callback.Query()
	q.Add("token", token)
	callback.RawQuery = q.Encode()

	err = m.options.Manager.Mailer().SendMagicLink(ctx, mailer.Email{
		To: input.Email,
	}, callback.String(), magic.Expiry)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to send magic link")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	return &LoginOutput{StatusCode: 200}, nil
}

func (m *Magic) callback(ctx context.Context, input *CallbackInput) (*CallbackOutput, error) {
	// Extract Fiber context for IP logging
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)
	m.logger.Debug().Str("IP", fiberCtx.IP()).Msg("callback")

	if m.options.Manager.Magic() == nil {
		return nil, huma.Error401Unauthorized("magic provider is not enabled")
	}

	f, err := m.options.Manager.Magic().CompleteFlow(ctx, input.Token)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, huma.Error404NotFound("flow does not exist")
		case errors.Is(err, magic.ErrInvalidToken):
			return nil, huma.Error401Unauthorized("invalid token")
		default:
			m.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("internal server error")
		}
	}

	if f.DeviceIdentifier != "" {
		if m.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
	}

	session, err := m.options.Manager.CreateSession(ctx, f, flow.MagicProvider)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to create session")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	output := &CallbackOutput{
		StatusCode: 307,
		Headers: MagicCallbackHeaders{
			Location: f.NextURL,
		},
	}

	if f.DeviceIdentifier != "" {
		// Device flow - complete the device flow but don't set cookie
		err = m.options.Manager.Device().CompleteFlow(ctx, f.DeviceIdentifier, session.Identifier)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("internal server error")
		}
	} else {
		// Regular flow - set session cookie
		token, err := m.options.Manager.SignSession(session)
		if err != nil {
			m.logger.Error().Err(err).Msg("error signing session")
			return nil, huma.Error500InternalServerError("internal server error")
		}

		output.Headers.SetCookie = &http.Cookie{
			Name:     models.SessionCookie,
			Value:    token,
			Expires:  session.ExpiresAt,
			Domain:   m.options.Endpoint,
			Secure:   m.options.TLS,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
	}

	return output, nil
}
