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

package github

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/grokify/go-pkce"
	"github.com/loopholelabs/auth/pkg/provider"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var _ provider.Provider = (*Github)(nil)

var (
	ErrInvalidResponse = errors.New("invalid response")
)

const (
	Key        = "github"
	GCInterval = time.Minute
	Expiry     = time.Minute * 5
)

var (
	defaultScopes = []string{"user:email"}
	defaultURL    = &url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   "/user/emails",
	}
)

type email struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

type Github struct {
	logger   *zerolog.Logger
	conf     *oauth2.Config
	database Database
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

func New(clientID string, clientSecret string, database Database, logger *zerolog.Logger) *Github {
	l := logger.With().Str("AUTH", "GITHUB-OAUTH-PROVIDER").Logger()
	ctx, cancel := context.WithCancel(context.Background())

	return &Github{
		logger: &l,
		conf: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       defaultScopes,
			Endpoint:     github.Endpoint,
		},
		database: database,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (g *Github) Key() provider.Key {
	return Key
}

func (g *Github) Start() error {
	g.wg.Add(1)
	go g.gc()
	return nil
}

func (g *Github) Stop() error {
	g.cancel()
	g.wg.Wait()
	return nil
}

func (g *Github) AuthURL(ctx context.Context, organization string) (string, error) {
	verifier := pkce.NewCodeVerifier()
	challenge := pkce.CodeChallengeS256(verifier)
	state := uuid.New().String()

	err := g.database.SetGithubFlow(ctx, state, organization, verifier, challenge)
	if err != nil {
		return "", err
	}

	return g.conf.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam(pkce.ParamCodeChallenge, challenge), oauth2.SetAuthURLParam(pkce.ParamCodeChallengeMethod, pkce.MethodS256)), nil
}

func (g *Github) GetUser(ctx context.Context, code string, state string) (string, string, error) {
	flow, err := g.database.GetGithubFlow(ctx, state)
	if err != nil {
		return "", "", err
	}

	err = g.database.DeleteGithubFlow(ctx, state)
	if err != nil {
		return "", "", err
	}

	token, err := g.conf.Exchange(ctx, code, oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, flow.Verifier))
	if err != nil {
		return "", "", err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    defaultURL,
		Header: http.Header{
			"Authorization": []string{"token " + token.AccessToken},
		},
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", "", ErrInvalidResponse
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}

	var emails []email
	err = json.Unmarshal(body, &emails)
	if err != nil {
		return "", "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, flow.Organization, nil
		}
	}

	return "", "", ErrInvalidResponse
}

func (g *Github) gc() {
	defer g.wg.Done()
	for {
		select {
		case <-g.ctx.Done():
			g.logger.Info().Msg("GC Stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := g.database.GCGithubFlow(g.ctx, Expiry)
			if err != nil {
				g.logger.Error().Err(err).Msg("failed to garbage collect expired github flows")
			} else {
				g.logger.Debug().Msgf("garbage collected %d expired github flows", deleted)
			}
		}
	}
}
