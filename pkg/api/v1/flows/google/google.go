//SPDX-License-Identifier: Apache-2.0

package google

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential/cookies"
	"github.com/loopholelabs/auth/pkg/manager/flow"
)

type Google struct {
	logger  types.Logger
	options options.Options
}

func New(options options.Options, logger types.Logger) *Google {
	return &Google{
		logger:  logger.SubLogger("GOOGLE"),
		options: options,
	}
}

func (g *Google) Register(prefixes []string, group huma.API) {
	prefixes = append(prefixes, "google")
	group = huma.NewGroup(group, "/google")

	loginPrefix := append(prefixes, "login") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(loginPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/login",
		Summary:       "initiate google OAuth login",
		Description:   "initiates the google OAuth flow and redirects google for authentication",
		Tags:          loginPrefix,
		DefaultStatus: 307,
		Errors:        []int{400, 401, 404, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("login", g.logger)},
	}, g.login)

	callbackPrefix := append(prefixes, "callback") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(callbackPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/callback",
		Summary:       "google OAuth callback",
		Description:   "handles the OAuth callback from google and creates a session",
		Tags:          callbackPrefix,
		DefaultStatus: 307,
		Errors:        []int{400, 401, 404, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("callback", g.logger)},
	}, g.callback)
}

func (g *Google) login(ctx context.Context, request *GoogleLoginRequest) (*GoogleLoginResponse, error) {
	if g.options.Manager.Google() == nil {
		return nil, huma.Error401Unauthorized("google provider is not enabled")
	}

	if request.Next == "" {
		return nil, huma.Error400BadRequest("invalid next url")
	}

	var err error
	var deviceIdentifier string

	if request.Code != "" {
		if len(request.Code) != 8 {
			return nil, huma.Error400BadRequest("invalid code")
		}
		if g.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
		deviceIdentifier, err = g.options.Manager.Device().ExistsFlow(ctx, request.Code)
		if err != nil {
			g.logger.Error().Err(err).Msg("error checking if flow exists")
			return nil, huma.Error500InternalServerError("error checking if flow exists")
		}
		if deviceIdentifier == "" {
			return nil, huma.Error404NotFound("device flow does not exist")
		}
	}

	redirect, err := g.options.Manager.Google().CreateFlow(ctx, deviceIdentifier, "", request.Next)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to get redirect")
		return nil, huma.Error500InternalServerError("failed to get redirect")
	}

	return &GoogleLoginResponse{
		Location: redirect,
	}, nil
}

func (g *Google) callback(ctx context.Context, request *GoogleCallbackRequest) (*GoogleCallbackResponse, error) {
	if g.options.Manager.Google() == nil {
		return nil, huma.Error401Unauthorized("google provider is not enabled")
	}

	if request.Code == "" {
		return nil, huma.Error400BadRequest("invalid code")
	}

	if request.State == "" {
		return nil, huma.Error400BadRequest("invalid state")
	}

	f, err := g.options.Manager.Google().CompleteFlow(ctx, request.State, request.Code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, huma.Error404NotFound("flow does not exist")
		}
		g.logger.Error().Err(err).Msg("failed to complete flow")
		return nil, huma.Error500InternalServerError("failed to complete flow")
	}

	if f.DeviceIdentifier != "" {
		if g.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
	}

	session, err := g.options.Manager.CreateSession(ctx, f, flow.GoogleProvider)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to create session")
		return nil, huma.Error500InternalServerError("failed to create session")
	}

	response := &GoogleCallbackResponse{
		Location: f.NextURL,
	}

	if f.DeviceIdentifier != "" {
		// Device flow - complete the device flow but don't set cookie
		err = g.options.Manager.Device().CompleteFlow(ctx, f.DeviceIdentifier, session.Identifier)
		if err != nil {
			g.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("internal server error")
		}
	} else {
		response.SessionCookie, err = cookies.Create(session, g.options)
		if err != nil {
			g.logger.Error().Err(err).Msg("error creating cookie")
			return nil, huma.Error500InternalServerError("error creating cookie")
		}
	}

	return response, nil
}
