//SPDX-License-Identifier: Apache-2.0

//nolint:revive
package magic

import (
	"github.com/loopholelabs/auth/pkg/api/models"
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
	Headers models.SessionWithRedirectHeaders
}
