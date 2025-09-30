//SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"database/sql"
	"errors"

	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/danielgtaylor/huma/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/db/pgxtypes"
	"github.com/loopholelabs/auth/pkg/api/middleware"
	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential/cookies"
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
		OperationID:   strings.Join(refreshPrefix, "-"),
		Method:        http.MethodPost,
		Path:          "/refresh",
		Summary:       "refreshes a session",
		Description:   "refreshes the expiration and embedded information for an active session",
		Tags:          refreshPrefix,
		DefaultStatus: 200,
		Errors:        []int{401, 500},
		Security: []map[string][]string{
			{"cookieAuth": {}},
		},
		Middlewares: huma.Middlewares{fiber.LogIP("refresh", g.logger), middleware.ValidateSession(group, g.options, g.logger)},
	}, g.refresh)

	revokePrefix := append(prefixes, "revoke") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(revokePrefix, "-"),
		Method:        http.MethodPost,
		Path:          "/revoke",
		Summary:       "revokes a session",
		Description:   "revokes an active session",
		Tags:          revokePrefix,
		DefaultStatus: 200,
		Errors:        []int{400, 401, 404, 500},
		Security: []map[string][]string{
			{"cookieAuth": {}},
		},
		Middlewares: huma.Middlewares{fiber.LogIP("revoke", g.logger), middleware.ValidateSession(group, g.options, g.logger)},
	}, g.revoke)
}

func (g *Session) info(ctx context.Context, _ *struct{}) (*SessionInfoResponse, error) {
	session, ok := middleware.GetSession(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("invalid session")
	}
	return &SessionInfoResponse{
		Body: SessionInfoResponseBody{
			Identifier:   session.Identifier,
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

	return nil, nil //nolint:nilnil
}

func (g *Session) revoke(ctx context.Context, request *SessionRevokeRequest) (*SessionRevokeResponse, error) {
	if len(request.Identifier) != 36 {
		return nil, huma.Error400BadRequest("invalid identifier")
	}

	session, ok := middleware.GetSession(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("invalid session")
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
	identifier := pgxtypes.UUIDFromString(request.Identifier)
	if !identifier.Valid {
		return nil, huma.Error400BadRequest("invalid identifier")
	}
	userIdentifier := pgxtypes.UUIDFromString(session.UserInfo.Identifier)
	if !userIdentifier.Valid {
		return nil, huma.Error401Unauthorized("invalid session")
	}

	revocableSession, err := qtx.GetSessionByIdentifierAndUserIdentifier(ctx, generated.GetSessionByIdentifierAndUserIdentifierParams{
		Identifier:     identifier,
		UserIdentifier: userIdentifier,
	})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			g.logger.Error().Err(err).Msg("error getting session")
			return nil, huma.Error500InternalServerError("error getting session")
		}
		return nil, huma.Error404NotFound("session not found")
	}

	num, err := qtx.DeleteSessionByIdentifier(ctx, revocableSession.Identifier)
	if err != nil {
		g.logger.Error().Err(err).Msg("error deleting session")
		return nil, huma.Error500InternalServerError("error deleting session")
	}
	if num == 0 {
		g.logger.Error().Msg("session not found")
		return nil, huma.Error404NotFound("session not found")
	}

	err = qtx.CreateSessionRevocation(ctx, generated.CreateSessionRevocationParams{
		SessionIdentifier: revocableSession.Identifier,
		ExpiresAt:         revocableSession.ExpiresAt,
	})
	if err != nil {
		g.logger.Error().Err(err).Msg("error revoking session")
		return nil, huma.Error500InternalServerError("error revoking session")
	}

	err = tx.Commit(ctx)
	if err != nil {
		g.logger.Error().Err(err).Msg("error committing transaction")
		return nil, huma.Error500InternalServerError("error accessing database")
	}

	identifierStr, err := pgxtypes.StringFromUUID(revocableSession.Identifier)
	if err != nil {
		return nil, huma.Error500InternalServerError("error processing session identifier")
	}
	expiresAt, err := pgxtypes.TimeFromTimestamp(revocableSession.ExpiresAt)
	if err != nil {
		return nil, huma.Error500InternalServerError("error processing session expiry")
	}
	createdAt, err := pgxtypes.TimeFromTimestamp(revocableSession.CreatedAt)
	if err != nil {
		return nil, huma.Error500InternalServerError("error processing session creation time")
	}

	return &SessionRevokeResponse{
		Body: SessionRevokeResponseBody{
			Identifier: identifierStr,
			Generation: uint32(revocableSession.Generation), //nolint:gosec // Generation is always non-negative
			ExpiresAt:  expiresAt,
			CreatedAt:  createdAt,
		},
	}, nil
}
