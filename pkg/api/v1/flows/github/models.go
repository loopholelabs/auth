//SPDX-License-Identifier: Apache-2.0

package github

import (
	"github.com/loopholelabs/auth/pkg/api/models"
)

type GithubLoginRequest struct {
	Next string `query:"next" required:"true" doc:"redirect URL after authentication"`
	Code string `query:"code" required:"false" minLength:"8" maxLength:"8" doc:"optional device flow code"`
}

type GithubCallbackRequest struct {
	Code  string `query:"code" required:"true" doc:"OAuth authorization code"`
	State string `query:"state" required:"true" doc:"OAuth state parameter"`
}

type GithubLoginHeaders struct {
	Location string `header:"Location" required:"true" doc:"redirect to github OAuth"`
}

type GithubLoginResponse struct {
	Headers GithubLoginHeaders
}

type GithubCallbackResponse struct {
	Headers models.SessionWithRedirectHeaders
}
