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
	"context"
	"encoding/json"
	"github.com/cli/oauth"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Config oauth2.Config

func NewConfig(clientID string, clientSecret string, authURL string, tokenURL string) *Config {
	return (*Config)(&oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   authURL,
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	})
}

type Flow oauth.Flow

type Token oauth2.Token

type Client interface {
	PostForm(url string, data url.Values) (*http.Response, error)
}

func NewToken(accessToken string, tokenType string, refreshToken string, expiry time.Time) *Token {
	return (*Token)(&oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		Expiry:       expiry,
	})
}

func UnmarshalToken(data []byte) (*Token, error) {
	t := new(oauth2.Token)
	return (*Token)(t), json.Unmarshal(data, t)
}

type TokenSource oauth2.TokenSource

func OAuthConfig(endpoint *oauth2.Endpoint, scopes []string, clientID string) *Config {
	return (*Config)(&oauth2.Config{
		ClientID: clientID,
		Endpoint: *endpoint,
		Scopes:   scopes,
	})
}

func DeviceFlow(hosts *oauth.Host, client Client, scopes []string, clientID string, displayCode func(string, string) error, browser func(string) error) *Flow {
	return (*Flow)(&oauth.Flow{
		Host:        hosts,
		Scopes:      scopes,
		ClientID:    clientID,
		DisplayCode: displayCode,
		BrowseURL:   browser,
		HTTPClient:  client,
	})
}

func GetToken(flow *Flow) (*Token, error) {
	flowToken, err := (*oauth.Flow)(flow).DeviceFlow()
	if err != nil {
		return nil, err
	}

	expiry, err := strconv.Atoi(flowToken.ExpiresIn)
	if err != nil {
		return nil, err
	}

	return (*Token)(&oauth2.Token{
		AccessToken:  flowToken.Token,
		TokenType:    flowToken.Type,
		RefreshToken: flowToken.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(expiry) * time.Second),
	}), nil
}

func NewTokenSource(ctx context.Context, config *Config, token *Token) TokenSource {
	return (*oauth2.Config)(config).TokenSource(ctx, (*oauth2.Token)(token))
}

func NewClient(ctx context.Context, source TokenSource) *http.Client {
	return oauth2.NewClient(ctx, source)
}
