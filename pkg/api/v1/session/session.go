//SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/loopholelabs/auth/pkg/api/middleware"
	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential/cookies"
	"github.com/loopholelabs/logging/types"
)

type Session struct {
	logger  types.Logger
	options options.Options
}

func New(options options.Options, logger types.Logger) *Session {
	return &Session{
		logger:  logger.SubLogger("SESSION"),
		options: options,
	}
}

func (g *Session) Register(prefixes []string, group huma.API) {
	prefixes = append(prefixes, "session")
	group = huma.NewGroup(group, "/session")

	infoPrefix := append(prefixes, "info") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(infoPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/info",
		Summary:       "retrieves session info",
		Description:   "retrieves session information",
		Tags:          infoPrefix,
		DefaultStatus: 200,
		Errors:        []int{401, 500},
		Security: []map[string][]string{
			{"cookieAuth": {}},
		},
		Middlewares: huma.Middlewares{fiber.LogIP("info", g.logger), middleware.ValidateSession(group, g.options, g.logger)},
	}, g.info)

	refreshPrefix := append(prefixes, "refresh") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(infoPrefix, "-"),
		Method:        http.MethodPost,
		Path:          "/refresh",
		Summary:       "refreshes session",
		Description:   "refreshes session information",
		Tags:          refreshPrefix,
		DefaultStatus: 200,
		Errors:        []int{401, 500},
		Security: []map[string][]string{
			{"cookieAuth": {}},
		},
		Middlewares: huma.Middlewares{fiber.LogIP("refresh", g.logger), middleware.ValidateSession(group, g.options, g.logger)},
	}, g.refresh)
}

func (g *Session) info(ctx context.Context, _ *struct{}) (*SessionInfoResponse, error) {
	session, ok := middleware.GetSession(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("invalid session")
	}
	return &SessionInfoResponse{
		Body: SessionInfoResponseBody{
			Name:         session.UserInfo.Name,
			Email:        session.UserInfo.Email,
			Organization: session.OrganizationInfo.Name,
			Role:         session.OrganizationInfo.Role.String(),
			Generation:   session.Generation,
			ExpiresAt:    session.ExpiresAt,
		},
	}, nil
}

func (g *Session) refresh(ctx context.Context, _ *struct{}) (*SessionRefreshResponse, error) {
	session, ok := middleware.GetSession(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("invalid session")
	}
	var err error
	if !middleware.GetSessionReSign(ctx) {
		session, err = g.options.Manager.RefreshSession(ctx, session)
		if err != nil {
			g.logger.Error().Err(err).Msg("unable to refresh session")
			return nil, huma.Error401Unauthorized("unable to refresh session")
		}
		cookie, err := cookies.Create(session, g.options)
		if err != nil {
			g.logger.Error().Err(err).Msg("error creating cookie")
			return nil, huma.Error500InternalServerError("error creating cookie")
		}
		return &SessionRefreshResponse{
			SessionCookie: cookie,
		}, nil
	}

	return nil, nil
}
