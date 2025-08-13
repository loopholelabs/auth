//SPDX-License-Identifier: Apache-2.0

package cookies

import (
	"errors"
	"net/http"

	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential"
)

var (
	ErrCreatingCookie = errors.New("error creating cookie")
)

const (
	SessionCookie = "authentication_session"
)

func Create(session credential.Session, options options.Options) (*http.Cookie, error) {
	token, err := options.Manager.SignSession(session)
	if err != nil {
		return nil, errors.Join(ErrCreatingCookie, err)
	}
	return &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Expires:  session.ExpiresAt,
		Domain:   options.Endpoint,
		Secure:   options.TLS,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}
