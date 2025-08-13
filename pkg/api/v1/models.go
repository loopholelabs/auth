//SPDX-License-Identifier: Apache-2.0

//nolint:revive
package v1

import (
	"net/http"

	"github.com/loopholelabs/auth/pkg/manager"
)

type V1LogoutRequest struct {
	SessionCookie string `cookie:"authentication_session" doc:"session cookie"`
}

type V1PublicResponseBody struct {
	PublicKey           string                       `json:"public_key" doc:"base64 encoded public key"`
	PreviousPublicKey   string                       `json:"previous_public_key,omitempty" doc:"base64 encoded previous public key"`
	RevokedSessions     []string                     `json:"revoked_sessions" doc:"list of revoked session IDs"`
	InvalidatedSessions []manager.InvalidatedSession `json:"invalidated_sessions" doc:"list of invalidated sessions"`
}

type V1PublicResponse struct {
	Body V1PublicResponseBody
}

type V1LogoutResponse struct {
	SessionCookie *http.Cookie `header:"Set-Cookie" doc:"clear session cookie"`
}
