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

func New(clientID string, clientSecret string, redirect string, database Database, logger *zerolog.Logger) *Github {
	l := logger.With().Str("AUTH", "GITHUB-OAUTH-PROVIDER").Logger()
	ctx, cancel := context.WithCancel(context.Background())

	return &Github{
		logger: &l,
		conf: &oauth2.Config{
			RedirectURL:  redirect,
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

func (g *Github) StartFlow(ctx context.Context, nextURL string, organization string, deviceIdentifier string) (string, error) {
	verifier := pkce.NewCodeVerifier()
	challenge := pkce.CodeChallengeS256(verifier)
	state := uuid.New().String()

	g.logger.Debug().Msgf("starting flow for state %s with org '%s' and device identifier '%s'", state, organization, deviceIdentifier)
	err := g.database.SetGithubFlow(ctx, state, verifier, challenge, nextURL, organization, deviceIdentifier)
	if err != nil {
		return "", err
	}

	return g.conf.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam(pkce.ParamCodeChallenge, challenge), oauth2.SetAuthURLParam(pkce.ParamCodeChallengeMethod, pkce.MethodS256)), nil
}

func (g *Github) CompleteFlow(ctx context.Context, code string, state string) (string, string, string, string, error) {
	g.logger.Debug().Msgf("completing flow for state %s", state)
	flow, err := g.database.GetGithubFlow(ctx, state)
	if err != nil {
		return "", "", "", "", err
	}

	g.logger.Debug().Msgf("found flow for state %s, deleting", state)
	err = g.database.DeleteGithubFlow(ctx, state)
	if err != nil {
		return "", "", "", "", err
	}

	g.logger.Debug().Msgf("exchanging code for token for state %s", state)
	token, err := g.conf.Exchange(ctx, code, oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, flow.Verifier))
	if err != nil {
		return "", "", "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", "", "", "", err
	}

	req.Header.Set("Authorization", "token "+token.AccessToken)

	g.logger.Debug().Msgf("fetching emails for state %s", state)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", "", "", "", ErrInvalidResponse
	}

	g.logger.Debug().Msgf("parsing emails for state %s", state)
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return "", "", "", "", err
	}

	var emails []email
	err = json.Unmarshal(body, &emails)
	if err != nil {
		return "", "", "", "", err
	}

	g.logger.Debug().Msgf("found %d emails for state %s", len(emails), state)

	for _, e := range emails {
		if e.Primary && e.Verified {
			g.logger.Debug().Msgf("found primary and verified email %s for state %s", e.Email, state)
			return e.Email, flow.Organization, flow.NextURL, flow.DeviceIdentifier, nil
		}
	}

	g.logger.Debug().Msgf("no primary and verified email found for state %s", state)
	return "", "", "", "", ErrInvalidResponse
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
