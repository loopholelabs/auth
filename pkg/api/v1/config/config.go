/*
	Copyright 2022 Loophole Labs

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
	a.app.Get("/", a.GetConfig)
}

func (a *Config) App() *fiber.App {
	return a.app
}

// GetConfig godoc
// @Summary      GetConfig gets the public configuration of the API
// @Description  GetConfig gets the public configuration of the API
// @Tags         config
// @Accept       json
// @Produce      json
// @Success      200  {array} models.GetConfigResponse
// @Failure      401  {string} string
// @Failure      500  {string} string
// @Router       /config [get]
func (a *Config) GetConfig(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GetConfig from %s", ctx.IP())
	res := new(models.GetConfigResponse)
	if a.options.Github() != nil {
		res.GithubEnabled = true
	}
	return ctx.JSON(res)
}
