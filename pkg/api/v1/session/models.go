//SPDX-License-Identifier: Apache-2.0

//nolint:revive
package session

import (
	"net/http"
	"time"
)

type SessionInfoResponseBody struct {
	Identifier   string    `json:"identifier" doc:"session identifier"`
	Name         string    `json:"name" doc:"user's name"`
	Email        string    `json:"email" doc:"user's email address"`
	Organization string    `json:"organization" doc:"user's organization"`
	Role         string    `json:"role" doc:"user's role in the organization"`
	Generation   uint32    `json:"generation" doc:"session generation"`
	ExpiresAt    time.Time `json:"expires_at" doc:"session's expiry time"`
}

type SessionInfoResponse struct {
	Body SessionInfoResponseBody
}

type SessionRefreshResponse struct {
	SessionCookie *http.Cookie `header:"Set-Cookie" doc:"session cookie"`
}

type SessionRevokeRequest struct {
	Identifier string `query:"identifier" required:"true" minLength:"36" maxLength:"36" doc:"session identifier"`
}

type SessionRevokeResponseBody struct {
	Identifier string    `json:"identifier" doc:"session identifier"`
	Generation uint32    `json:"generation" doc:"session generation"`
	ExpiresAt  time.Time `json:"expires_at" doc:"session expiry time"`
	CreatedAt  time.Time `json:"created_at" doc:"session creation time"`
}

type SessionRevokeResponse struct {
	Body SessionRevokeResponseBody
}
