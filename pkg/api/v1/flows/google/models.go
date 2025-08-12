//SPDX-License-Identifier: Apache-2.0

package google

import (
	"github.com/loopholelabs/auth/pkg/api/models"
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

type GoogleLoginHeaders struct {
	Location string `header:"Location" required:"true" doc:"redirect to google OAuth"`
}

type GoogleLoginResponse struct {
	Headers GoogleLoginHeaders
}

type GoogleCallbackResponse struct {
	Headers models.SessionWithRedirectHeaders
}
