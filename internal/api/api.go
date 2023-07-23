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

package api

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	v1 "github.com/loopholelabs/auth/internal/api/v1"
	v1Docs "github.com/loopholelabs/auth/internal/api/v1/docs"
	v1Options "github.com/loopholelabs/auth/internal/api/v1/options"
	"github.com/loopholelabs/auth/internal/controller"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/flow/device"
	"github.com/loopholelabs/auth/pkg/flow/github"
	"github.com/loopholelabs/auth/pkg/flow/google"
	"github.com/loopholelabs/auth/pkg/flow/magic"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
	"net"
)

const (
	V1Path = "/v1"
)

type Options struct {
	Disabled             bool
	ListenAddress        string
	Endpoint             string
	TLS                  bool
	DefaultNextURL       string
	DeviceCodeEnabled    bool
	GithubEnabled        bool
	GithubClientID       string
	GithubClientSecret   string
	GoogleEnabled        bool
	GoogleClientID       string
	GoogleClientSecret   string
	MagicLinkEnabled     bool
	MagicLinkFrom        string
	MagicLinkProjectName string
	MagicLinkProjectURL  string
	PostmarkAPIToken     string
	PostmarkTemplateID   int
	PostmarkTag          string
}

type API struct {
	logger  *zerolog.Logger
	options *Options
	app     *fiber.App

	storage    storage.Storage
	controller *controller.Controller

	deviceProvider *device.Device
	githubProvider *github.Github
	googleProvider *google.Google
	magicProvider  *magic.Magic

	v1Options *v1Options.Options
}

func New(options *Options, storage storage.Storage, controller *controller.Controller, logger *zerolog.Logger) *API {
	l := logger.With().Str("AUTH", "API").Logger()

	scheme := "http"
	if options.TLS {
		scheme = "https"
	}

	var deviceProvider *device.Device
	if options.DeviceCodeEnabled {
		deviceProvider = device.New(storage, &l)
	}

	var githubProvider *github.Github
	if options.GithubEnabled {
		githubProvider = github.New(storage, &github.Options{
			ClientID:     options.GithubClientID,
			ClientSecret: options.GithubClientSecret,
			Redirect:     fmt.Sprintf("%s://%s/v1/github/callback", scheme, options.Endpoint),
		}, &l)
	}

	var googleProvider *google.Google
	if options.GoogleEnabled {
		googleProvider = google.New(storage, &google.Options{
			ClientID:     options.GoogleClientID,
			ClientSecret: options.GoogleClientSecret,
			Redirect:     fmt.Sprintf("%s://%s/v1/google/callback", scheme, options.Endpoint),
		}, &l)
	}

	var magicProvider *magic.Magic
	if options.MagicLinkEnabled {
		magicProvider = magic.New(storage, &magic.Options{
			APIToken:   options.PostmarkAPIToken,
			TemplateID: options.PostmarkTemplateID,
			Tag:        options.PostmarkTag,
			From:       options.MagicLinkFrom,
			Project:    options.MagicLinkProjectName,
			ProjectURL: options.MagicLinkProjectURL,
		}, &l)
	}

	v1Opts := v1Options.New(controller, deviceProvider, githubProvider, googleProvider, magicProvider, options.Endpoint, options.TLS, options.DefaultNextURL)

	return &API{
		logger:         &l,
		options:        options,
		app:            utils.DefaultFiberApp(),
		controller:     controller,
		storage:        storage,
		deviceProvider: deviceProvider,
		githubProvider: githubProvider,
		googleProvider: googleProvider,
		magicProvider:  magicProvider,
		v1Options:      v1Opts,
	}
}

func (s *API) Start() error {
	listener, err := net.Listen("tcp", s.options.ListenAddress)
	if err != nil {
		return err
	}
	v1Docs.SwaggerInfoauthAPI.Host = s.options.Endpoint
	v1Docs.SwaggerInfoauthAPI.Schemes = []string{"http"}
	if s.options.TLS {
		v1Docs.SwaggerInfoauthAPI.Schemes = []string{"https"}
	}

	if s.deviceProvider != nil {
		err = s.deviceProvider.Start()
		if err != nil {
			return fmt.Errorf("failed to start device provider: %w", err)
		}
	}

	if s.githubProvider != nil {
		err = s.githubProvider.Start()
		if err != nil {
			return fmt.Errorf("failed to start github provider: %w", err)
		}
	}

	if s.googleProvider != nil {
		err = s.googleProvider.Start()
		if err != nil {
			return fmt.Errorf("failed to start google provider: %w", err)
		}
	}

	if s.magicProvider != nil {
		err = s.magicProvider.Start()
		if err != nil {
			return fmt.Errorf("failed to start magic provider: %w", err)
		}
	}

	s.app.Use(cors.New())
	s.app.Mount(V1Path, v1.New(s.v1Options, s.logger).App())

	return s.app.Listener(listener)
}

func (s *API) Stop() error {
	err := s.app.Shutdown()
	if err != nil {
		return err
	}

	if s.deviceProvider != nil {
		err = s.deviceProvider.Stop()
		if err != nil {
			return err
		}
	}

	if s.githubProvider != nil {
		err = s.githubProvider.Stop()
		if err != nil {
			return err
		}
	}

	if s.googleProvider != nil {
		err = s.googleProvider.Stop()
		if err != nil {
			return err
		}
	}

	if s.magicProvider != nil {
		err = s.magicProvider.Stop()
		if err != nil {
			return err
		}
	}

	return nil
}
