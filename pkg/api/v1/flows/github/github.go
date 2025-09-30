//SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db/pgxtypes"
	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential/cookies"
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
		Errors:        []int{400, 401, 404, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("callback", g.logger)},
	}, g.callback)
}

func (g *Github) login(ctx context.Context, request *GithubLoginRequest) (*GithubLoginResponse, error) {
	if g.options.Manager.Github() == nil {
		return nil, huma.Error401Unauthorized("github provider is not enabled")
	}

	if request.Next == "" {
		return nil, huma.Error400BadRequest("invalid next url")
	}

	var err error
	var deviceUUID pgtype.UUID

	if request.Code != "" {
		if len(request.Code) != 8 {
			return nil, huma.Error400BadRequest("invalid code")
		}
		if g.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
		deviceIdentifier, err := g.options.Manager.Device().ExistsFlow(ctx, request.Code)
		if err != nil {
			g.logger.Error().Err(err).Msg("error checking if flow exists")
			return nil, huma.Error500InternalServerError("error checking if flow exists")
		}
		if deviceIdentifier == "" {
			return nil, huma.Error404NotFound("device flow does not exist")
		}

		// Convert device identifier to pgtype.UUID
		deviceUUID, err = pgxtypes.UUIDFromString(deviceIdentifier)
		if err != nil {
			g.logger.Error().Err(err).Str("device_id", deviceIdentifier).Msg("invalid device identifier from ExistsFlow")
			return nil, huma.Error500InternalServerError("invalid device identifier")
		}
	} else {
		// No device flow - use invalid UUID
		deviceUUID = pgtype.UUID{Valid: false}
	}

	// Call manager function
	// Input validated: deviceUUID is a valid pgtype.UUID or Valid:false
	// Input validated: userUUID is Valid:false (no user identifier)
	// Non-PGX type: request.Next is a URL string (not for database)
	redirect, err := g.options.Manager.Github().CreateFlow(ctx, deviceUUID, pgtype.UUID{Valid: false}, request.Next)
	if err != nil {
		g.logger.Error().Err(err).Msg("failed to get redirect")
		return nil, huma.Error500InternalServerError("failed to get redirect")
	}

	return &GithubLoginResponse{
		Location: redirect,
	}, nil
}

func (g *Github) callback(ctx context.Context, request *GithubCallbackRequest) (*GithubCallbackResponse, error) {
	if g.options.Manager.Github() == nil {
		return nil, huma.Error401Unauthorized("github provider is not enabled")
	}

	if request.Code == "" {
		return nil, huma.Error400BadRequest("invalid code")
	}

	if request.State == "" {
		return nil, huma.Error400BadRequest("invalid state")
	}

	// Validate and convert state parameter to pgtype.UUID
	stateUUID, err := pgxtypes.UUIDFromString(request.State)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid state identifier")
	}

	// Call manager function
	// Input validated: stateUUID is a valid pgtype.UUID
	// Non-PGX type: request.Code is OAuth authorization code (not for database)
	f, err := g.options.Manager.Github().CompleteFlow(ctx, stateUUID, request.Code)
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
		Location: f.NextURL,
	}

	if f.DeviceIdentifier != "" {
		// Device flow - complete the device flow but don't set cookie
		// Convert identifiers to pgtype.UUID
		deviceUUID, err := pgxtypes.UUIDFromString(f.DeviceIdentifier)
		if err != nil {
			g.logger.Error().Err(err).Str("device_id", f.DeviceIdentifier).Msg("invalid device identifier from flow")
			return nil, huma.Error500InternalServerError("invalid device identifier")
		}
		sessionUUID, err := pgxtypes.UUIDFromString(session.Identifier)
		if err != nil {
			g.logger.Error().Err(err).Str("session_id", session.Identifier).Msg("invalid session identifier")
			return nil, huma.Error500InternalServerError("invalid session identifier")
		}

		// Call manager function
		// Input validated: deviceUUID and sessionUUID are valid pgtype.UUIDs
		err = g.options.Manager.Device().CompleteFlow(ctx, deviceUUID, sessionUUID)
		if err != nil {
			g.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("failed to complete flow")
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
