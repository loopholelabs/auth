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

package google

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/grokify/go-pkce"
	"github.com/loopholelabs/auth/pkg/flow"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/logging/types"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
	"sync"
	"time"
)

var _ flow.Flow = (*Google)(nil)

var (
	ErrInvalidResponse = errors.New("invalid response")
)

const (
	Key        flow.Key = "google"
	GCInterval          = time.Minute
	Expiry              = time.Minute * 5
)

var (
	defaultScopes = []string{"https://www.googleapis.com/auth/userinfo.email"}
)

type email struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

type Options struct {
	ClientID     string
	ClientSecret string
	Redirect     string
}

type Google struct {
	logger  types.Logger
	storage storage.Google
	options *Options
	conf    *oauth2.Config
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func New(storage storage.Google, options *Options, logger types.Logger) *Google {
	ctx, cancel := context.WithCancel(context.Background())

	return &Google{
		logger:  logger.SubLogger("GOOGLE-OAUTH-PROVIDER"),
		storage: storage,
		options: options,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (g *Google) Key() flow.Key {
	return Key
}

func (g *Google) Start() error {
	if g.options == nil {
		return flow.ErrInvalidOptions
	}

	if g.options.ClientID == "" {
		return flow.ErrInvalidOptions
	}

	if g.options.ClientSecret == "" {
		return flow.ErrInvalidOptions
	}

	if g.options.Redirect == "" {
		return flow.ErrInvalidOptions
	}

	g.conf = &oauth2.Config{
		RedirectURL:  g.options.Redirect,
		ClientID:     g.options.ClientID,
		ClientSecret: g.options.ClientSecret,
		Scopes:       defaultScopes,
		Endpoint:     google.Endpoint,
	}

	g.wg.Add(1)
	go g.gc()
	return nil
}

func (g *Google) Stop() error {
	g.cancel()
	g.wg.Wait()
	return nil
}

func (g *Google) StartFlow(ctx context.Context, nextURL string, organization string, deviceIdentifier string) (string, error) {
	verifier, err := pkce.NewCodeVerifier(-1)
	if err != nil {
		return "", err
	}
	challenge := pkce.CodeChallengeS256(verifier)
	state := uuid.New().String()

	g.logger.Debug().Msgf("starting flow for state %s with org '%s' and device identifier '%s'", state, organization, deviceIdentifier)
	err = g.storage.SetGoogleFlow(ctx, state, verifier, challenge, nextURL, organization, deviceIdentifier)
	if err != nil {
		return "", err
	}

	return g.conf.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam(pkce.ParamCodeChallenge, challenge), oauth2.SetAuthURLParam(pkce.ParamCodeChallengeMethod, pkce.MethodS256)), nil
}

func (g *Google) CompleteFlow(ctx context.Context, code string, state string) (string, string, string, string, error) {
	g.logger.Debug().Msgf("completing flow for state %s", state)
	f, err := g.storage.GetGoogleFlow(ctx, state)
	if err != nil {
		return "", "", "", "", err
	}

	g.logger.Debug().Msgf("found flow for state %s, deleting", state)
	err = g.storage.DeleteGoogleFlow(ctx, state)
	if err != nil {
		return "", "", "", "", err
	}

	g.logger.Debug().Msgf("exchanging code for token for state %s", state)
	token, err := g.conf.Exchange(ctx, code, oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, f.Verifier))
	if err != nil {
		return "", "", "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return "", "", "", "", err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	g.logger.Debug().Msgf("fetching emails for state %s", state)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", "", "", "", ErrInvalidResponse
	}

	g.logger.Debug().Msgf("parsing email for state %s", state)
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return "", "", "", "", err
	}

	var e email
	err = json.Unmarshal(body, &e)
	if err != nil {
		return "", "", "", "", err
	}

	return e.Email, f.Organization, f.NextURL, f.DeviceIdentifier, nil
}

func (g *Google) gc() {
	defer g.wg.Done()
	for {
		select {
		case <-g.ctx.Done():
			g.logger.Info().Msg("GC Stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := g.storage.GCGoogleFlow(g.ctx, Expiry)
			if err != nil {
				g.logger.Error().Err(err).Msg("failed to garbage collect expired google flows")
			} else {
				g.logger.Debug().Msgf("garbage collected %d expired google flows", deleted)
			}
		}
	}
}
