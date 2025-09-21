//SPDX-License-Identifier: Apache-2.0

package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/db/pgxtypes"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/middleware"
	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/manager/role"
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

	updatePrefix := append(prefixes, "update") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(updatePrefix, "-"),
		Method:        http.MethodPost,
		Path:          "/update",
		Summary:       "updates user info",
		Description:   "updates user information",
		Tags:          updatePrefix,
		DefaultStatus: 200,
		Errors:        []int{400, 401, 404, 500},
		Security: []map[string][]string{
			{"cookieAuth": {}},
		},
		Middlewares: huma.Middlewares{fiber.LogIP("update", g.logger), middleware.ValidateSession(group, g.options, g.logger)},
	}, g.update)
}

func (g *User) info(ctx context.Context, _ *struct{}) (*UserInfoResponse, error) {
	session, ok := middleware.GetSession(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("invalid session")
	}

	user, err := g.options.Manager.Database().Queries.GetUserByIdentifier(ctx, pgxtypes.UUIDFromString(session.UserInfo.Identifier))
	if err != nil {
		g.logger.Error().Err(err).Msg("error retrieving user info")
		return nil, huma.Error500InternalServerError("error retrieving user info")
	}

	organizations, err := g.options.Manager.Database().Queries.GetOrganizationsForUserIdentifier(ctx, pgxtypes.UUIDFromString(session.UserInfo.Identifier))
	if err != nil {
		g.logger.Error().Err(err).Msg("error retrieving user memberships")
		return nil, huma.Error500InternalServerError("error retrieving user memberships")
	}

	defaultOrganization, err := g.options.Manager.Database().Queries.GetOrganizationByIdentifier(ctx, user.DefaultOrganizationIdentifier)
	if err != nil {
		g.logger.Error().Err(err).Msg("error retrieving default organization")
		return nil, huma.Error500InternalServerError("error retrieving default organization")
	}

	identities, err := g.options.Manager.Database().Queries.GetAllIdentitiesByUserIdentifier(ctx, pgxtypes.UUIDFromString(session.UserInfo.Identifier))
	if err != nil {
		g.logger.Error().Err(err).Msg("error retrieving user identities")
		return nil, huma.Error500InternalServerError("error retrieving user identities")
	}

	var organizationInfo []OrganizationInfo
	for _, organization := range organizations {
		organizationInfo = append(organizationInfo, OrganizationInfo{
			Name:      organization.Name,
			CreatedAt: pgxtypes.TimeFromTimestamp(organization.CreatedAt),
			Role:      organization.MembershipRole,
			JoinedAt:  pgxtypes.TimeFromTimestamp(organization.MembershipCreatedAt),
		})
	}

	var identityInfos []IdentityInfo
	for _, identity := range identities {
		var verifiedEmails []string
		err = json.Unmarshal(identity.VerifiedEmails, &verifiedEmails)
		if err != nil {
			g.logger.Error().Err(err).Msg("error retrieving user verified emails")
			return nil, huma.Error500InternalServerError("error retrieving user verified emails")
		}
		identityInfos = append(identityInfos, IdentityInfo{
			Provider:       string(identity.Provider),
			VerifiedEmails: verifiedEmails,
			CreatedAt:      pgxtypes.TimeFromTimestamp(identity.CreatedAt),
		})
	}

	return &UserInfoResponse{
		Body: UserInfoResponseBody{
			Name:      session.UserInfo.Name,
			Email:     session.UserInfo.Email,
			LastLogin: pgxtypes.TimeFromTimestamp(user.LastLogin),
			CreatedAt: pgxtypes.TimeFromTimestamp(user.CreatedAt),
			DefaultOrganization: OrganizationInfo{
				Name:      defaultOrganization.Name,
				CreatedAt: pgxtypes.TimeFromTimestamp(defaultOrganization.CreatedAt),
				Role:      role.OwnerRole.String(),
				JoinedAt:  pgxtypes.TimeFromTimestamp(user.CreatedAt),
			},
			Organizations: organizationInfo,
			Identities:    identityInfos,
		},
	}, nil
}

func (g *User) update(ctx context.Context, request *UserUpdateRequest) (*struct{}, error) {
	session, ok := middleware.GetSession(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("invalid session")
	}

	if request.Name == "" && request.Email == "" {
		return nil, huma.Error400BadRequest("updated user name or email is required")
	}

	if request.Email != "" {
		if len(request.Email) < 3 {
			return nil, huma.Error400BadRequest("invalid email")
		}
	}

	tx, err := g.options.Manager.Database().BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		g.logger.Error().Err(err).Msg("error beginning transaction")
		return nil, huma.Error500InternalServerError("error accessing database")
	}

	defer func() {
		err := tx.Rollback(ctx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			g.logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()

	qtx := g.options.Manager.Database().Queries.WithTx(tx)

	if request.Email != "" {
		identities, err := qtx.GetAllIdentitiesByUserIdentifier(ctx, pgxtypes.UUIDFromString(session.UserInfo.Identifier))
		if err != nil {
			g.logger.Error().Err(err).Msg("error retrieving user identities")
			return nil, huma.Error500InternalServerError("error retrieving user identities")
		}
		valid := false
		for _, identity := range identities {
			var verifiedEmails []string
			err = json.Unmarshal(identity.VerifiedEmails, &verifiedEmails)
			if err != nil {
				g.logger.Error().Err(err).Msg("error retrieving user verified emails")
				return nil, huma.Error500InternalServerError("error retrieving user verified emails")
			}
			isValid := false
			for _, verifiedEmail := range verifiedEmails {
				if verifiedEmail == request.Email {
					isValid = true
					break
				}
			}
			if isValid {
				valid = true
				break
			}
		}
		if !valid {
			return nil, huma.Error400BadRequest("invalid email")
		}

		num, err := qtx.UpdateUserPrimaryEmailByIdentifier(ctx, generated.UpdateUserPrimaryEmailByIdentifierParams{
			PrimaryEmail: request.Email,
			Identifier:   pgxtypes.UUIDFromString(session.UserInfo.Identifier),
		})
		if err != nil {
			g.logger.Error().Err(err).Msg("error updating user primary email")
			return nil, huma.Error500InternalServerError("error updating user primary email")
		}
		if num == 0 {
			g.logger.Error().Msg("unable to find user")
			return nil, huma.Error404NotFound("unable to find user")
		}
	}

	if request.Name != "" {
		num, err := qtx.UpdateUserNameByIdentifier(ctx, generated.UpdateUserNameByIdentifierParams{
			Name:       request.Name,
			Identifier: pgxtypes.UUIDFromString(session.UserInfo.Identifier),
		})
		if err != nil {
			g.logger.Error().Err(err).Msg("error updating user name")
			return nil, huma.Error500InternalServerError("error updating user name")
		}
		if num == 0 {
			g.logger.Error().Msg("unable to find user")
			return nil, huma.Error404NotFound("unable to find user")
		}
	}

	numInvalidations, err := qtx.CreateSessionInvalidationsFromSessionByUserIdentifier(ctx, pgxtypes.UUIDFromString(session.UserInfo.Identifier))
	if err != nil {
		g.logger.Error().Err(err).Msg("error creating session invalidations")
		return nil, huma.Error500InternalServerError("error creating session invalidations")
	}
	numSessions, err := qtx.IncrementAllSessionGenerationByUserIdentifier(ctx, pgxtypes.UUIDFromString(session.UserInfo.Identifier))
	if err != nil {
		g.logger.Error().Err(err).Msg("error incrementing session generation")
		return nil, huma.Error500InternalServerError("error incrementing session generation")
	}
	if numInvalidations != numSessions {
		g.logger.Error().Msg("session invalidations don't match session count")
		return nil, huma.Error500InternalServerError("invalid session state")
	}

	err = tx.Commit(ctx)
	if err != nil {
		g.logger.Error().Err(err).Msg("error committing transaction")
		return nil, huma.Error500InternalServerError("error accessing database")
	}

	return nil, nil //nolint:nilnil
}
