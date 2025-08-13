//SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/loopholelabs/auth/pkg/manager/role"

	"github.com/loopholelabs/auth/pkg/api/middleware"
	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/logging/types"
)

type User struct {
	logger  types.Logger
	options options.Options
}

func New(options options.Options, logger types.Logger) *User {
	return &User{
		logger:  logger.SubLogger("USER"),
		options: options,
	}
}

func (g *User) Register(prefixes []string, group huma.API) {
	prefixes = append(prefixes, "user")
	group = huma.NewGroup(group, "/user")

	infoPrefix := append(prefixes, "info") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(infoPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/info",
		Summary:       "retrieves user info",
		Description:   "retrieves user information",
		Tags:          infoPrefix,
		DefaultStatus: 200,
		Errors:        []int{401, 500},
		Security: []map[string][]string{
			{"cookieAuth": {}},
		},
		Middlewares: huma.Middlewares{fiber.LogIP("info", g.logger), middleware.ValidateSession(group, g.options, g.logger)},
	}, g.info)
}

func (g *User) info(ctx context.Context, _ *struct{}) (*UserInfoResponse, error) {
	session, ok := middleware.GetSession(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("invalid session")
	}

	user, err := g.options.Manager.Database().Queries.GetUserByIdentifier(ctx, session.UserInfo.Identifier)
	if err != nil {
		g.logger.Error().Err(err).Msg("error retrieving user info")
		return nil, huma.Error500InternalServerError("error retrieving user info")
	}

	organizations, err := g.options.Manager.Database().Queries.GetOrganizationsForUserIdentifier(ctx, session.UserInfo.Identifier)
	if err != nil {
		g.logger.Error().Err(err).Msg("error retrieving user memberships")
		return nil, huma.Error500InternalServerError("error retrieving user memberships")
	}

	defaultOrganization, err := g.options.Manager.Database().Queries.GetOrganizationByIdentifier(ctx, user.DefaultOrganizationIdentifier)
	if err != nil {
		g.logger.Error().Err(err).Msg("error retrieving default organization")
		return nil, huma.Error500InternalServerError("error retrieving default organization")
	}

	var organizationInfo []OrganizationInfo
	for _, organization := range organizations {
		organizationInfo = append(organizationInfo, OrganizationInfo{
			Name:      organization.Name,
			CreatedAt: organization.CreatedAt,
			Role:      organization.MembershipRole,
			JoinedAt:  organization.MembershipCreatedAt,
		})
	}

	return &UserInfoResponse{
		Body: UserInfoResponseBody{
			Name:      session.UserInfo.Name,
			Email:     session.UserInfo.Email,
			LastLogin: user.LastLogin,
			CreatedAt: user.CreatedAt,
			DefaultOrganization: OrganizationInfo{
				Name:      defaultOrganization.Name,
				CreatedAt: defaultOrganization.CreatedAt,
				Role:      role.OwnerRole.String(),
				JoinedAt:  user.CreatedAt,
			},
			Organizations: organizationInfo,
		},
	}, nil
}
