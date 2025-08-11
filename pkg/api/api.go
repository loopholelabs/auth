//SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1"
)

var (
	ErrCreatingAPI = errors.New("error creating api")
	ErrStartingAPI = errors.New("error starting API")
	ErrStoppingAPI = errors.New("error stopping API")
)

const (
	V1Path = "/v1"
)

type API struct {
	logger types.Logger
	app    *fiber.App

	options options.Options
}

func New(o options.Options, logger types.Logger) (*API, error) {
	l := logger.SubLogger("API")
	if !o.IsValid() {
		return nil, errors.Join(ErrCreatingAPI, options.ErrInvalidOptions)
	}

	return &API{
		logger:  l,
		options: o,
		app:     utils.DefaultFiberApp(),
	}, nil
}

func (s *API) Start(listenAddress string) error {
	listener, err := net.Listen("tcp", listenAddress) //nolint:noctx
	if err != nil {
		return errors.Join(err, ErrStartingAPI)
	}

	s.app.Use(cors.New())
	s.app.Mount(V1Path, v1.New(s.options, s.logger).App())

	return s.app.Listener(listener)
}

func (s *API) Close() error {
	err := s.app.Shutdown()
	if err != nil {
		return errors.Join(ErrStoppingAPI, err)
	}
	return nil
}
