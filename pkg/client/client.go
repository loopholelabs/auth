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

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/go-openapi/runtime/client"
	"github.com/loopholelabs/auth/pkg/client/discover"
	"github.com/loopholelabs/auth/pkg/token/tokenKind"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func ContextClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

type CompatibleClient struct {
	transport http.RoundTripper
}

func NewCompatibleClient(transport http.RoundTripper) *CompatibleClient {
	return &CompatibleClient{transport: transport}
}

func (c *CompatibleClient) PostForm(uri string, data url.Values) (*http.Response, error) {
	if !(strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://")) {
		uri = "https://" + uri
	}
	req, err := http.NewRequest("POST", uri, nil)
	if err != nil {
		return nil, err
	}
	req.Form = make(url.Values)
	for k, v := range data {
		req.Form.Set(k, v[0])
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(bytes.NewBufferString(req.Form.Encode()))
	return c.transport.RoundTrip(req)
}

func UnauthenticatedClient(endpoint string, basePath string, schemes []string, tlsConfig *tls.Config) (*client.Runtime, *http.Client) {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{Transport: transport}

	if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	}
	if strings.HasPrefix(endpoint, "http://") {
		endpoint = strings.TrimPrefix(endpoint, "http://")
	}
	return client.NewWithClient(endpoint, basePath, schemes, httpClient), httpClient
}

func AuthenticatedClient(endpoint string, basePath string, schemes []string, tlsConfig *tls.Config, authEndpoint string, clientID string, kind tokenKind.Kind, token *Token) (TokenSource, *client.Runtime, error) {
	_, hc := UnauthenticatedClient(endpoint, basePath, schemes, tlsConfig)

	var conf *Config
	switch kind {
	case tokenKind.OAuthKind:
		discovery, err := discover.Discover(hc.Transport, fmt.Sprintf("https://%s", authEndpoint))
		if err != nil {
			return nil, nil, err
		}
		conf = NewConfig(clientID, "", discovery.Auth, discovery.Token)
	case tokenKind.APITokenKind, tokenKind.ServiceTokenKind:
		conf = NewConfig(clientID, "", fmt.Sprintf("https://%s/exchange", authEndpoint), fmt.Sprintf("https://%s/refresh", authEndpoint))
	default:
		return nil, nil, fmt.Errorf("unknown token kind: %s", kind)
	}

	clientContext := ContextClient(context.Background(), &http.Client{
		Transport: hc.Transport,
	})
	tokenSource := NewTokenSource(clientContext, conf, token)

	return tokenSource, client.NewWithClient(endpoint, basePath, schemes, NewClient(clientContext, tokenSource)), nil
}
