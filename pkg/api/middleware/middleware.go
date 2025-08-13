//SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential"
	"github.com/loopholelabs/auth/pkg/credential/cookies"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/manager"
)

type sessionKey struct{}

func ValidateSession(api huma.API, options options.Options, logger types.Logger) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		sessionCookie, err := huma.ReadCookie(ctx, cookies.SessionCookie)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, huma.Error401Unauthorized("invalid session cookie").Error())
			return
		}

		session, reSign, err := options.Manager.ValidateSession(ctx.Context(), sessionCookie.Value)
		if err != nil {
			if !errors.Is(err, manager.ErrRevokedSession) {
				logger.Error().Err(err).Msg("error validating session")
			}
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, huma.Error401Unauthorized("invalid session").Error())
			return
		}

		var cookie *http.Cookie
		if reSign {
			cookie, err = cookies.Create(session, options)
			if err != nil {
				logger.Error().Err(err).Msg("error creating cookie")
				_ = huma.WriteErr(api, ctx, http.StatusInternalServerError, huma.Error500InternalServerError("error creating cookie").Error())
				return
			}
			ctx.AppendHeader("Set-Cookie", cookie.String())
		}

		next(huma.WithValue(ctx, sessionKey{}, session))
	}
}

func GetSession(ctx context.Context) (credential.Session, bool) {
	sessionInterface := ctx.Value(sessionKey{})
	if sessionInterface == nil {
		return credential.Session{}, false
	}
	session, ok := sessionInterface.(credential.Session)
	return session, ok
}
