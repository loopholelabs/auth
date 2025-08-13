//SPDX-License-Identifier: Apache-2.0

//nolint:revive
package magic

import (
	"net/http"
)

type MagicLoginRequest struct {
	Email string `query:"email" required:"true" doc:"email address"`
	Next  string `query:"next" required:"true" doc:"redirect URL after authentication"`
	Code  string `query:"code" required:"false" minLength:"8" maxLength:"8" doc:"optional device flow code"`
}

type MagicCallbackRequest struct {
	Token string `query:"token" required:"true" doc:"magic link token"`
}

type MagicCallbackResponse struct {
	SessionCookie *http.Cookie `header:"Set-Cookie" doc:"session cookie"`
	Location      string       `header:"Location" required:"true" doc:"redirect to next URL"`
}
