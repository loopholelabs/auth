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
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/api"
	"github.com/loopholelabs/auth/internal/controller"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/logging/types"
)

var (
	ErrDisabled = errors.New("auth is disabled")
)

type Options struct {
	LogName       string
	Disabled      bool
	SessionDomain string
	TLS           bool
	API           *api.Options
}

type Auth struct {
	logger  types.Logger
	options *Options
	storage storage.Storage

	controller *controller.Controller
	api        *api.API

	ctx    context.Context
	cancel context.CancelFunc
}

func New(options *Options, storage storage.Storage, logger types.Logger) (*Auth, error) {
	l := logger.SubLogger(options.LogName)
	if options.Disabled {
		l.Warn().Msg("disabled")
		return nil, ErrDisabled
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := controller.New(options.SessionDomain, options.TLS, storage, l)
	a := &Auth{
		logger:     l,
		options:    options,
		storage:    storage,
		controller: c,
		ctx:        ctx,
		cancel:     cancel,
	}

	return a, nil
}

func (m *Auth) Start() error {
	m.logger.Debug().Msg("starting auth controller")
	err := m.controller.Start()
	if err != nil {
		return err
	}

	if !m.options.API.Disabled {
		m.api = api.New(m.options.API, m.storage, m.controller, m.logger)
		m.logger.Debug().Msgf("starting auth API on %s", m.options.API.ListenAddress)
		return m.api.Start()
	}

	return nil
}

func (m *Auth) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}

	if m.controller != nil {
		err := m.controller.Stop()
		if err != nil {
			return err
		}
	}

	if !m.options.API.Disabled {
		err := m.api.Stop()
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Auth) Validate(ctx *fiber.Ctx) error {
	return m.controller.Validate(ctx)
}

func (m *Auth) ManualValidate(ctx *fiber.Ctx) (bool, error) {
	return m.controller.ManualValidate(ctx)
}
