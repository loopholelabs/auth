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

package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/api"
	v1Options "github.com/loopholelabs/auth/internal/api/v1/options"
	"github.com/loopholelabs/auth/internal/controller"
	"github.com/loopholelabs/auth/pkg/apikey"
	"github.com/loopholelabs/auth/pkg/flow/device"
	"github.com/loopholelabs/auth/pkg/flow/github"
	"github.com/loopholelabs/auth/pkg/flow/google"
	"github.com/loopholelabs/auth/pkg/flow/magic"
	"github.com/loopholelabs/auth/pkg/kind"
	"github.com/loopholelabs/auth/pkg/servicesession"
	"github.com/loopholelabs/auth/pkg/session"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
)

var (
	ErrDisabled = errors.New("auth is disabled")
)

type Options struct {
	LogName              string
	Disabled             bool
	ListenAddress        string
	Endpoint             string
	TLS                  bool
	SessionDomain        string
	DefaultNextURL       string
	GithubClientID       string
	GithubClientSecret   string
	GoogleClientID       string
	GoogleClientSecret   string
	DeviceCodeEnabled    bool
	PostmarkAPIToken     string
	PostmarkTemplateID   int
	PostmarkTag          string
	MagicLinkFrom        string
	MagicLinkProjectName string
	MagicLinkProjectURL  string
}

type Auth struct {
	logger  *zerolog.Logger
	options *Options
	storage storage.Storage

	controller *controller.Controller
	api        *api.API

	ctx    context.Context
	cancel context.CancelFunc
}

func New(options *Options, storage storage.Storage, logger *zerolog.Logger) (*Auth, error) {
	l := logger.With().Str(options.LogName, "AUTH").Logger()
	if options.Disabled {
		l.Warn().Msg("disabled")
		return nil, ErrDisabled
	}

	scheme := "http"
	if options.TLS {
		scheme = "https"
	}

	var githubProvider v1Options.Github
	if options.GithubClientID != "" && options.GithubClientSecret != "" {
		ghp := github.New(storage, &github.Options{
			ClientID:     options.GithubClientID,
			ClientSecret: options.GithubClientSecret,
			Redirect:     fmt.Sprintf("%s://%s/v1/github/callback", scheme, options.Endpoint),
		}, &l)
		err := ghp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start github provider: %w", err)
		}
		githubProvider = func() *github.Github {
			return ghp
		}
	}

	var googleProvider v1Options.Google
	if options.GoogleClientID != "" && options.GoogleClientSecret != "" {
		ggp := google.New(storage, &google.Options{
			ClientID:     options.GoogleClientID,
			ClientSecret: options.GoogleClientSecret,
			Redirect:     fmt.Sprintf("%s://%s/v1/google/callback", scheme, options.Endpoint),
		}, &l)
		err := ggp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start google provider: %w", err)
		}
		googleProvider = func() *google.Google {
			return ggp
		}
	}

	var deviceProvider v1Options.Device
	if options.DeviceCodeEnabled {
		dp := device.New(storage, &l)
		err := dp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start device code provider: %w", err)
		}
		deviceProvider = func() *device.Device {
			return dp
		}
	}

	var magicProvider v1Options.Magic
	if options.PostmarkAPIToken != "" && options.PostmarkTemplateID != 0 && options.MagicLinkFrom != "" && options.MagicLinkProjectName != "" && options.MagicLinkProjectURL != "" {
		mp := magic.New(storage, &magic.Options{
			APIToken:   options.PostmarkAPIToken,
			TemplateID: options.PostmarkTemplateID,
			Tag:        options.PostmarkTag,
			From:       options.MagicLinkFrom,
			Project:    options.MagicLinkProjectName,
			ProjectURL: options.MagicLinkProjectURL,
		}, &l)
		err := mp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start magic link provider: %w", err)
		}
		magicProvider = func() *magic.Magic {
			return mp
		}
	}

	c := controller.New(options.SessionDomain, options.TLS, storage, &l)
	err := c.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start controller: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := api.New(v1Options.New(c, options.DefaultNextURL, options.Endpoint, options.TLS, v1Options.WithGithub(githubProvider), v1Options.WithGoogle(googleProvider), v1Options.WithDevice(deviceProvider), v1Options.WithMagic(magicProvider)), &l)

	return &Auth{
		logger:     &l,
		options:    options,
		storage:    storage,
		controller: c,
		api:        a,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (m *Auth) StartAPI() error {
	return m.api.Start(m.options.ListenAddress)
}

func (m *Auth) StopAPI() error {
	if m.cancel != nil {
		m.cancel()
	}

	if m.api != nil {
		err := m.api.Stop()
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Auth) Cleanup() error {
	if m.controller != nil {
		err := m.controller.Stop()
		if err != nil {
			return err
		}
	}

	if m.storage != nil {
		err := m.storage.Shutdown()
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Auth) Delimiter() string {
	return controller.KeyDelimiterString
}

func (m *Auth) Validate(ctx *fiber.Ctx) error {
	return m.controller.Validate(ctx)
}

func (m *Auth) ManualValidate(ctx *fiber.Ctx) (bool, error) {
	return m.controller.ManualValidate(ctx)
}

func (m *Auth) AuthAvailable(ctx *fiber.Ctx) bool {
	return m.controller.AuthAvailable(ctx)
}

func (m *Auth) GetAuthFromContext(ctx *fiber.Ctx) (kind.Kind, string, string, error) {
	return m.controller.GetAuthFromContext(ctx)
}

func (m *Auth) GetSessionFromContext(ctx *fiber.Ctx) (*session.Session, error) {
	return m.controller.GetSessionFromContext(ctx)
}

func (m *Auth) GetAPIKeyFromContext(ctx *fiber.Ctx) (*apikey.APIKey, error) {
	return m.controller.GetAPIKeyFromContext(ctx)
}

func (m *Auth) GetServiceSessionFromContext(ctx *fiber.Ctx) (*servicesession.ServiceSession, error) {
	return m.controller.GetServiceSessionFromContext(ctx)
}
