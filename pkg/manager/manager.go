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

package manager

import (
	"context"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth"
	"github.com/loopholelabs/auth/internal/api"
	"github.com/loopholelabs/auth/internal/api/v1/options"
	"github.com/loopholelabs/auth/internal/controller"
	"github.com/loopholelabs/auth/internal/database"
	"github.com/loopholelabs/auth/internal/provider/device"
	"github.com/loopholelabs/auth/internal/provider/github"
	"github.com/loopholelabs/auth/internal/provider/google"
	"github.com/loopholelabs/auth/internal/provider/magic"
	"github.com/loopholelabs/auth/pkg/apikey"
	"github.com/loopholelabs/auth/pkg/servicesession"
	"github.com/loopholelabs/auth/pkg/session"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
	"sync"
)

var (
	ErrInvalidOptions = errors.New("invalid options")
)

type Options struct {
	Endpoint             string
	TLS                  bool
	SessionDomain        string
	DefaultNextURL       string
	DatabaseURL          string
	Storage              storage.Storage
	GithubClientID       string
	GithubClientSecret   string
	GoogleClientID       string
	GoogleClientSecret   string
	DeviceCode           bool
	PostmarkAPIToken     string
	PostmarkTemplateID   int
	PostmarkTag          string
	MagicLinkFrom        string
	MagicLinkProjectName string
	MagicLinkProjectURL  string
}

type Manager struct {
	logger     *zerolog.Logger
	controller *controller.Controller
	database   *database.Database
	api        *api.API
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func New(opts *Options, logger *zerolog.Logger) (*Manager, error) {
	l := logger.With().Str("AUTH", "MANAGER").Logger()

	if opts.DatabaseURL == "" {
		return nil, fmt.Errorf("%w: database url is required", ErrInvalidOptions)
	}

	if opts.DefaultNextURL == "" {
		return nil, fmt.Errorf("%w: default next url is required", ErrInvalidOptions)
	}

	if opts.Storage == nil {
		return nil, fmt.Errorf("%w: storage is required", ErrInvalidOptions)
	}

	if opts.Endpoint == "" {
		return nil, fmt.Errorf("%w: endpoint is required", ErrInvalidOptions)
	}

	if opts.SessionDomain == "" {
		return nil, fmt.Errorf("%w: session domain is required", ErrInvalidOptions)
	}

	db, err := database.New(opts.DatabaseURL, &l)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	scheme := "http"
	if opts.TLS {
		scheme = "https"
	}

	var githubProvider options.Github
	if opts.GithubClientID != "" && opts.GithubClientSecret != "" {
		ghp := github.New(opts.GithubClientID, opts.GithubClientSecret, fmt.Sprintf("%s://%s/v1/github/callback", scheme, opts.Endpoint), db, &l)
		err = ghp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start github provider: %w", err)
		}
		githubProvider = func() *github.Github {
			return ghp
		}
	}

	var googleProvider options.Google
	if opts.GoogleClientID != "" && opts.GoogleClientSecret != "" {
		ggp := google.New(opts.GoogleClientID, opts.GoogleClientSecret, fmt.Sprintf("%s://%s/v1/google/callback", scheme, opts.Endpoint), db, &l)
		err = ggp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start google provider: %w", err)
		}
		googleProvider = func() *google.Google {
			return ggp
		}
	}

	var deviceProvider options.Device
	if opts.DeviceCode {
		dp := device.New(db, &l)
		err = dp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start device code provider: %w", err)
		}
		deviceProvider = func() *device.Device {
			return dp
		}
	}

	var magicProvider options.Magic
	if opts.PostmarkAPIToken != "" && opts.PostmarkTemplateID != 0 && opts.MagicLinkFrom != "" && opts.MagicLinkProjectName != "" && opts.MagicLinkProjectURL != "" {
		mp := magic.New(db, &magic.Options{
			APIToken:   opts.PostmarkAPIToken,
			TemplateID: opts.PostmarkTemplateID,
			Tag:        opts.PostmarkTag,
			From:       opts.MagicLinkFrom,
			Project:    opts.MagicLinkProjectName,
			ProjectURL: opts.MagicLinkProjectURL,
		}, &l)
		err = mp.Start()
		if err != nil {
			return nil, fmt.Errorf("failed to start magic link provider: %w", err)
		}
		magicProvider = func() *magic.Magic {
			return mp
		}
	}

	c := controller.New(opts.SessionDomain, opts.TLS, opts.Storage, &l)
	err = c.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start controller: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	a := api.New(options.New(c, opts.DefaultNextURL, opts.Endpoint, opts.TLS, options.WithGithub(githubProvider), options.WithGoogle(googleProvider), options.WithDevice(deviceProvider), options.WithMagic(magicProvider)), &l)

	return &Manager{
		logger:     &l,
		controller: c,
		database:   db,
		api:        a,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (m *Manager) StartAPI(addr string) error {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		err := m.api.Start(addr)
		if err != nil {
			m.logger.Error().Err(err).Msg("API failed to start")
		}
	}()

	return nil
}

func (m *Manager) StopAPI() error {
	if m.cancel != nil {
		m.cancel()
	}

	if m.api != nil {
		err := m.api.Stop()
		if err != nil {
			return err
		}
	}

	m.wg.Wait()
	return nil
}

func (m *Manager) Cleanup() error {
	if m.controller != nil {
		err := m.controller.Stop()
		if err != nil {
			return err
		}
	}

	if m.database != nil {
		err := m.database.Shutdown()
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) Delimiter() string {
	return controller.KeyDelimiterString
}

func (m *Manager) Validate(ctx *fiber.Ctx) error {
	return m.controller.Validate(ctx)
}

func (m *Manager) ManualValidate(ctx *fiber.Ctx) (bool, error) {
	return m.controller.ManualValidate(ctx)
}

func (m *Manager) AuthAvailable(ctx *fiber.Ctx) bool {
	return m.controller.AuthAvailable(ctx)
}

func (m *Manager) GetAuthFromContext(ctx *fiber.Ctx) (auth.Kind, string, string, error) {
	return m.controller.GetAuthFromContext(ctx)
}

func (m *Manager) GetSessionFromContext(ctx *fiber.Ctx) (*session.Session, error) {
	return m.controller.GetSessionFromContext(ctx)
}

func (m *Manager) GetAPIKeyFromContext(ctx *fiber.Ctx) (*apikey.APIKey, error) {
	return m.controller.GetAPIKeyFromContext(ctx)
}

func (m *Manager) GetServiceSessionFromContext(ctx *fiber.Ctx) (*servicesession.ServiceSession, error) {
	return m.controller.GetServiceSessionFromContext(ctx)
}
