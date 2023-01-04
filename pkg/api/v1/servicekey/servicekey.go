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

package servicekey

import (
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/pkg/api/v1/options"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
)

type ServiceKey struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *ServiceKey {
	l := logger.With().Str("ROUTER", "SERVICEKEY").Logger()
	i := &ServiceKey{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *ServiceKey) init() {
	a.logger.Debug().Msg("initializing")
	a.app.Get("/login", a.ServiceKeyLogin)
}

func (a *ServiceKey) App() *fiber.App {
	return a.app
}

// ServiceKeyLogin godoc
// @Summary      ServiceKeyLogin logs in a user with their Service Key
// @Description  ServiceKeyLogin logs in a user with their Service Key
// @Tags         apikey, login
// @Accept       json
// @Produce      json
// @Param        organization query string false "Organization"
// @Success      200 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /servicekey/login [post]
func (a *ServiceKey) ServiceKeyLogin(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received ServiceKeyLogin from %s", ctx.IP())
	return nil
}
