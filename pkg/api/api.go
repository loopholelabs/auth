//SPDX-License-Identifier: Apache-2.0

package api

import (
	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/utils"
)

const (
	V1Path = "/v1"
)

type API struct {
	logger types.Logger
	app    *fiber.App
	db     *db.DB

	tls      bool
	endpoint string
}

func New(endpoint string, tls bool, db *db.DB, logger types.Logger) *API {
	l := logger.SubLogger("API")

	return &API{
		logger:   l,
		endpoint: endpoint,
		tls:      tls,
		app:      utils.DefaultFiberApp(),
		db:       db,
	}
}

func (s *API) Start(listenAddress string) error {
	listener, err := net.Listen("tcp", listenAddress) //nolint:noctx
	if err != nil {
		return err
	}

	s.app.Use(cors.New())
	return s.app.Listener(listener)
}

func (s *API) Stop() error {
	err := s.app.Shutdown()
	if err != nil {
		return err
	}
	return nil
}
