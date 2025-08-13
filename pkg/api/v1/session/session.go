//SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/loopholelabs/auth/pkg/api/middleware"
	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
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
