//SPDX-License-Identifier: Apache-2.0

//nolint:revive
package google

import (
	"net/http"
)

// Request types

type GoogleLoginRequest struct {
	Next string `query:"next" required:"true" doc:"redirect URL after authentication"`
	Code string `query:"code" required:"false" minLength:"8" maxLength:"8" doc:"optional device flow code"`
}

type GoogleCallbackRequest struct {
	Code  string `query:"code" required:"true" doc:"OAuth authorization code"`
	State string `query:"state" required:"true" doc:"OAuth state parameter"`
}

type GoogleLoginResponse struct {
	Location string `header:"Location" required:"true" doc:"redirect to github OAuth"`
}

type GoogleCallbackResponse struct {
	SessionCookie *http.Cookie `header:"Set-Cookie" doc:"session cookie"`
	Location      string       `header:"Location" required:"true" doc:"redirect to next URL"`
}
