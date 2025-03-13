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

package magic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/loopholelabs/auth/pkg/flow"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/logging/types"
	"github.com/mattevans/postmark-go"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"sync"
	"time"
)

var _ flow.Flow = (*Magic)(nil)

var (
	ErrInvalidSecret = errors.New("invalid secret")
)

const (
	templateEmailURL = "https://api.postmarkapp.com/email/withTemplate"
	userAgent        = "loopholelabs-auth"
)

const (
	Key        flow.Key = "magic"
	GCInterval          = time.Minute
	Expiry              = time.Minute * 5
)

type Options struct {
	APIToken   string
	From       string
	Project    string
	ProjectURL string
	TemplateID int
	Tag        string
}

type Magic struct {
	logger    types.Logger
	storage   storage.Magic
	options   *Options
	client    *postmark.Client
	transport *http.Transport
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

func New(storage storage.Magic, options *Options, logger types.Logger) *Magic {
	ctx, cancel := context.WithCancel(context.Background())

	return &Magic{
		logger:  logger.SubLogger("MAGIC-LINK-PROVIDER"),
		storage: storage,
		options: options,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (g *Magic) Key() flow.Key {
	return Key
}

func (g *Magic) Start() error {
	if g.options == nil {
		return flow.ErrInvalidOptions
	}

	if g.options.APIToken == "" {
		return flow.ErrInvalidOptions
	}

	if g.options.From == "" {
		return flow.ErrInvalidOptions
	}

	if g.options.TemplateID == 0 {
		return flow.ErrInvalidOptions
	}

	g.transport = &http.Transport{
		ResponseHeaderTimeout: time.Second * 5,
	}

	g.wg.Add(1)
	go g.gc()
	return nil
}

func (g *Magic) Stop() error {
	g.transport.CloseIdleConnections()
	g.cancel()
	g.wg.Wait()
	return nil
}

func (g *Magic) StartFlow(ctx context.Context, email string, ip string, nextURL string, organization string, deviceIdentifier string) ([]byte, error) {
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	_, err = g.storage.GetMagicFlow(ctx, email)
	if err == nil {
		err = g.storage.DeleteMagicFlow(ctx, email)
		if err != nil {
			return nil, err
		}
	}

	g.logger.Debug().Msgf("starting flow for %s (ip: %s) with org '%s' and device identifier '%s'", email, ip, organization, deviceIdentifier)
	err = g.storage.SetMagicFlow(ctx, email, salt, hash, ip, nextURL, organization, deviceIdentifier)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

func (g *Magic) SendMagic(ctx context.Context, url string, email string, ip string, token string) (err error) {
	g.logger.Debug().Msgf("sending magic for %s and ip %s", email, ip)

	data, err := json.Marshal(&postmark.Email{
		From:       g.options.From,
		To:         email,
		Tag:        g.options.Tag,
		TemplateID: g.options.TemplateID,
		TemplateModel: map[string]interface{}{
			"project_url": g.options.ProjectURL,
			"project":     g.options.Project,
			"time":        time.Now().Format(time.RFC3339),
			"ip":          ip,
			"url":         fmt.Sprintf("%s/v1/magic/callback?token=%s", url, token),
		},
		TrackOpens: true,
		Metadata: map[string]string{
			"client-ip":    ip,
			"client-email": email,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to encode email: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", templateEmailURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Postmark-Server-Token", g.options.APIToken)
	req.Header.Add("User-Agent", userAgent)

	resp, err := g.transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("failed to close response body: %w", closeErr)
		}
	}()

	err = postmark.CheckResponse(resp)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (g *Magic) CompleteFlow(ctx context.Context, email string, secret []byte) (string, string, string, error) {
	g.logger.Debug().Msgf("completing flow for email %s", email)
	f, err := g.storage.GetMagicFlow(ctx, email)
	if err != nil {
		return "", "", "", err
	}

	if bcrypt.CompareHashAndPassword(f.Hash, append(f.Salt, secret...)) != nil {
		return "", "", "", ErrInvalidSecret
	}

	g.logger.Debug().Msgf("validated flow for %s, deleting", email)
	err = g.storage.DeleteMagicFlow(ctx, email)
	if err != nil {
		return "", "", "", err
	}

	return f.Organization, f.NextURL, f.DeviceIdentifier, nil
}

func (g *Magic) gc() {
	defer g.wg.Done()
	for {
		select {
		case <-g.ctx.Done():
			g.logger.Info().Msg("GC Stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := g.storage.GCMagicFlow(g.ctx, Expiry)
			if err != nil {
				g.logger.Error().Err(err).Msg("failed to garbage collect expired magic flows")
			} else {
				g.logger.Debug().Msgf("garbage collected %d expired magic flows", deleted)
			}
		}
	}
}
