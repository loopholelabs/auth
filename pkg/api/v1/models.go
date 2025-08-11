//SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net/http"

	"github.com/loopholelabs/auth/pkg/validator"
)

type HealthResponse struct {
	StatusCode int `json:"-" default:"200"`
}

type PublicResponseBody struct {
	PublicKey           string                         `json:"public_key" doc:"Base64 encoded public key"`
	PreviousPublicKey   string                         `json:"previous_public_key,omitempty" doc:"Base64 encoded previous public key"`
	RevokedSessions     []string                       `json:"revoked_sessions" doc:"List of revoked session IDs"`
	InvalidatedSessions []validator.InvalidatedSession `json:"invalidated_sessions" doc:"List of invalidated sessions"`
}

type PublicResponse struct {
	StatusCode int `json:"-" default:"200"`
	Body       PublicResponseBody
}

type LogoutRequest struct {
	// Cookie will be extracted from the Fiber context
}

type LogoutHeaders struct {
	SetCookie *http.Cookie `header:"Set-Cookie,omitempty" doc:"Clear session cookie"`
}

type LogoutResponse struct {
	StatusCode int `json:"-" default:"200"`
	Headers    LogoutHeaders
}
