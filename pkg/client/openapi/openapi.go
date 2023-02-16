/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package openapi

import (
	"crypto/tls"
	"fmt"
	"github.com/go-openapi/runtime/client"
	"github.com/loopholelabs/auth"
	"github.com/loopholelabs/auth/internal/cookiejar"
	"github.com/loopholelabs/auth/pkg/client/session"
	"golang.org/x/net/publicsuffix"
	"net/http"
	netCookieJar "net/http/cookiejar"
	"net/url"
)

func UnauthenticatedClient(endpoint string, basePath string, schemes []string, tlsConfig *tls.Config) *client.Runtime {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// cookiejar.New never returns an error
	jar, _ := cookiejar.New(&netCookieJar.Options{
		PublicSuffixList: publicsuffix.List,
	})

	hc := &http.Client{
		Transport: transport,
		Jar:       jar,
	}

	c := client.NewWithClient(endpoint, basePath, schemes, hc)
	c.Jar = jar

	return c
}

func AuthenticatedClient(cookieURL *url.URL, endpoint string, basePath string, schemes []string, tlsConfig *tls.Config, session *session.Session) (*client.Runtime, error) {
	c := UnauthenticatedClient(endpoint, basePath, schemes, tlsConfig)

	switch session.Kind {
	case auth.KindSession:
		c.Jar.SetCookies(cookieURL, []*http.Cookie{
			{
				Name:     "auth-session",
				Value:    session.Value,
				Domain:   cookieURL.Host,
				Expires:  session.Expiry,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			},
		})
	case auth.KindServiceSession, auth.KindAPIKey:
		c.DefaultAuthentication = client.APIKeyAuth("Authorization", "header", fmt.Sprintf("Bearer %s", session.Value))
	default:
		return nil, fmt.Errorf("unknown session kind: %s", session.Kind)
	}

	return c, nil
}
