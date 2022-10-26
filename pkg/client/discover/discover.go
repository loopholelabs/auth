/*
	Copyright 2022 Loophole Labs

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

package discover

import (
	"fmt"
	"github.com/cli/oauth"
	"golang.org/x/oauth2"
	"io"
	"mime"
	"net/http"
	"strings"
)

type Discovery struct {
	Issuer            string   `json:"issuer"`
	Auth              string   `json:"authorization_endpoint"`
	Token             string   `json:"token_endpoint"`
	Keys              string   `json:"jwks_uri"`
	UserInfo          string   `json:"userinfo_endpoint"`
	DeviceEndpoint    string   `json:"device_authorization_endpoint"`
	GrantTypes        []string `json:"grant_types_supported"`
	ResponseTypes     []string `json:"response_types_supported"`
	Subjects          []string `json:"subject_types_supported"`
	IDTokenAlgs       []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeAlgs []string `json:"code_challenge_methods_supported"`
	Scopes            []string `json:"scopes_supported"`
	AuthMethods       []string `json:"token_endpoint_auth_methods_supported"`
	Claims            []string `json:"claims_supported"`
}

func Discover(transport http.RoundTripper, issuer string) (*Discovery, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if err == nil {
			return nil, fmt.Errorf("%s: %s", resp.Status, string(body))
		}
		return nil, fmt.Errorf("%s: %v", resp.Status, err)
	}

	d := new(Discovery)
	if err != nil {
		ct := resp.Header.Get("Content-Type")
		mediaType, _, parseErr := mime.ParseMediaType(ct)
		if parseErr == nil && mediaType == "application/json" {
			return nil, fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
		}
		return nil, fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
	}

	return d, nil
}

func (d *Discovery) GetHosts() *oauth.Host {
	return &oauth.Host{
		DeviceCodeURL: d.DeviceEndpoint,
		AuthorizeURL:  d.Auth,
		TokenURL:      d.Token,
	}
}

func (d *Discovery) GetScopes() []string {
	return d.Scopes
}

func (d *Discovery) GetEndpoints() *oauth2.Endpoint {
	return &oauth2.Endpoint{
		AuthURL:  d.Auth,
		TokenURL: d.Token,
	}
}
