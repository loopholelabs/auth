//SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/credential/cookies"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/models"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/manager/flow"
)

type Github struct {
	logger  types.Logger
	options options.Options
}

func New(options options.Options, logger types.Logger) *Github {
	return &Github{
		logger:  logger.SubLogger("GITHUB"),
		options: options,
	}
}

func (g *Github) Register(prefixes []string, group huma.API) {
	prefixes = append(prefixes, "github")
	group = huma.NewGroup(group, "/github")

	loginPrefix := append(prefixes, "login") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(loginPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/login",
		Summary:       "initiate github OAuth flow",
		Description:   "initiates the github OAuth flow and redirects github for authentication",
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
		Summary:       "github OAuth callback",
		Description:   "handles the OAuth callback from github and creates a session",
		Tags:          callbackPrefix,
		DefaultStatus: 307,
		Errors:        []int{401, 404, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("callback", g.logger)},
	}, g.callback)
}

func (g *Github) login(ctx context.Context, input *GithubLoginRequest) (*GithubLoginResponse, error) {
	if g.options.Manager.Github() == nil {
		return nil, huma.Error401Unauthorized("github provider is not enabled")
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
			return nil, huma.Error500InternalServerError("error checking if flow exists")
		}
		if deviceIdentifier == "" {
			return nil, huma.Error404NotFound("device flow does not exist")
		}
	}

	redirect, err := g.options.Manager.Github().CreateFlow(ctx, deviceIdentifier, "", input.Next)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to get redirect")
		return nil, huma.Error500InternalServerError("failed to get redirect")
	}

	return &GithubLoginResponse{
		Headers: GithubLoginHeaders{
			Location: redirect,
		},
	}, nil
}

func (g *Github) callback(ctx context.Context, input *GithubCallbackRequest) (*GithubCallbackResponse, error) {
	if g.options.Manager.Github() == nil {
		return nil, huma.Error401Unauthorized("github provider is not enabled")
	}

	f, err := g.options.Manager.Github().CompleteFlow(ctx, input.State, input.Code)
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

	session, err := g.options.Manager.CreateSession(ctx, f, flow.GithubProvider)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to create session")
		return nil, huma.Error500InternalServerError("failed to create session")
	}

	response := &GithubCallbackResponse{
		Headers: models.SessionWithRedirectHeaders{
			Location: f.NextURL,
		},
	}

	if f.DeviceIdentifier != "" {
		// Device flow - complete the device flow but don't set cookie
		err = g.options.Manager.Device().CompleteFlow(ctx, f.DeviceIdentifier, session.Identifier)
		if err != nil {
			g.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("failed to complete flow")
		}
	} else {
		response.Headers.SetCookie, err = cookies.Create(session, g.options)
		if err != nil {
			g.logger.Error().Err(err).Msg("error creating cookie")
			return nil, huma.Error500InternalServerError("error creating cookie")
		}
	}

	return response, nil
}
