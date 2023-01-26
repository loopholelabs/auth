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
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	v1 "github.com/loopholelabs/auth/pkg/api/v1"
	v1Docs "github.com/loopholelabs/auth/pkg/api/v1/docs"
	v1Options "github.com/loopholelabs/auth/pkg/api/v1/options"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
	"net"
)

const (
	V1Path = "/v1"
)

type API struct {
	logger    *zerolog.Logger
	app       *fiber.App
	v1Options *v1Options.Options
}

func New(v1Options *v1Options.Options, logger *zerolog.Logger) *API {
	l := logger.With().Str("AUTH", "API").Logger()
	s := &API{
		logger:    &l,
		app:       utils.DefaultFiberApp(),
		v1Options: v1Options,
	}

	s.init()

	return s
}

func (s *API) init() {
	s.logger.Debug().Msg("initializing")
	s.app.Use(cors.New())
	s.app.Mount(V1Path, v1.New(s.v1Options, s.logger).App())
}

func (s *API) Start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	v1Docs.SwaggerInfoapi.Host = s.v1Options.Endpoint()
	v1Docs.SwaggerInfoapi.Schemes = []string{"http"}
	if s.v1Options.TLS() {
		v1Docs.SwaggerInfoapi.Schemes = []string{"https"}
	}
	return s.app.Listener(listener)
}

func (s *API) Stop() error {
	err := s.app.Shutdown()
	if err != nil {
		return err
	}

	err = s.v1Options.Manager().Stop()
	if err != nil {
		return err
	}

	if s.v1Options.Github() != nil {
		err = s.v1Options.Github().Stop()
		if err != nil {
			return err
		}
	}

	if s.v1Options.Device() != nil {
		err = s.v1Options.Device().Stop()
		if err != nil {
			return err
		}
	}

	return nil
}
