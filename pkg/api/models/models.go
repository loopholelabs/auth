//SPDX-License-Identifier: Apache-2.0

package models

import (
	"net/http"
)

type SessionHeaders struct {
	SetCookie *http.Cookie `header:"Set-Cookie" required:"true" doc:"session cookie"`
}

type SessionWithRedirectHeaders struct {
	SetCookie *http.Cookie `header:"Set-Cookie,omitempty" doc:"session cookie"`
	Location  string       `header:"Location" required:"true" doc:"redirect to next URL"`
}
