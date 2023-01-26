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

package config

import (
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/api/v1/options"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
)

type Config struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Config {
	l := logger.With().Str("ROUTER", "CONFIG").Logger()
	i := &Config{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *Config) init() {
	a.logger.Debug().Msg("initializing")
	a.app.Get("/", a.Config)
}

func (a *Config) App() *fiber.App {
	return a.app
}

// Config godoc
// @Summary      Config gets the public configuration of the API
// @Description  Config gets the public configuration of the API
// @Tags         config
// @Accept       json
// @Produce      json
// @Success      200  {array} models.ConfigResponse
// @Failure      401  {string} string
// @Failure      500  {string} string
// @Router       /config [get]
func (a *Config) Config(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received Config from %s", ctx.IP())
	res := &models.ConfigResponse{
		Endpoint:       a.options.Endpoint(),
		DefaultNextURL: a.options.NextURL(),
	}
	if a.options.Github() != nil {
		res.GithubEnabled = true
	}

	if a.options.Google() != nil {
		res.GoogleEnabled = true
	}

	if a.options.Magic() != nil {
		res.MagicEnabled = true
	}

	if a.options.Device() != nil {
		res.DeviceEnabled = true
	}

	return ctx.JSON(res)
}
