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

package v1

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth"
	"github.com/loopholelabs/auth/pkg/api/v1/config"
	"github.com/loopholelabs/auth/pkg/api/v1/device"
	"github.com/loopholelabs/auth/pkg/api/v1/docs"
	"github.com/loopholelabs/auth/pkg/api/v1/github"
	"github.com/loopholelabs/auth/pkg/api/v1/options"
	"github.com/loopholelabs/auth/pkg/api/v1/servicekey"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
)

//go:generate swag init -g v1.go -o docs --parseDependency --instanceName api -d ./
type V1 struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *V1 {
	l := logger.With().Str("VERSION", "v1").Logger()
	v := &V1{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	v.init()

	return v
}

// @title Auth API V1
// @version 1.0
// @description Auth API, V1
// @termsOfService https://loopholelabs.io/privacy
// @contact.name API Support
// @contact.email admin@loopholelabs.io
// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @schemes https
// @BasePath /v1
func (v *V1) init() {
	v.logger.Debug().Msg("initializing")

	v.app.Mount("/config", config.New(v.options, v.logger).App())
	v.app.Mount("/github", github.New(v.options, v.logger).App())
	v.app.Mount("/device", device.New(v.options, v.logger).App())
	v.app.Mount("/servicekey", servicekey.New(v.options, v.logger).App())

	v.app.Post("/logout", v.Logout)
	v.app.Post("/loggedin", v.options.Manager().Validate, v.IsLoggedIn)

	v.app.Get("/swagger.json", func(ctx *fiber.Ctx) error {
		ctx.Response().Header.SetContentType("application/json")
		return ctx.SendString(docs.SwaggerInfoapi.ReadDoc())
	})
}

func (v *V1) App() *fiber.App {
	return v.app
}

// Logout godoc
// @Summary      Logout logs out a user
// @Description  Logout logs out a user
// @Tags         logout
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /logout [post]
func (v *V1) Logout(ctx *fiber.Ctx) error {
	v.logger.Debug().Msgf("received Logout from %s", ctx.IP())

	err := v.options.Manager().LogoutSession(ctx)
	if err != nil {
		return err
	}

	err = v.options.Manager().LogoutServiceKeySession(ctx)
	if err != nil {
		return err
	}

	return ctx.SendString("logged out")
}

// IsLoggedIn godoc
// @Summary      IsLoggedIn checks if a user is logged in
// @Description  IsLoggedIn checks if a user is logged in
// @Tags         login
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /loggedin [post]
func (v *V1) IsLoggedIn(ctx *fiber.Ctx) error {
	v.logger.Debug().Msgf("received IsLoggedIn from %s", ctx.IP())
	userID, ok := ctx.Locals(auth.UserContextKey).(string)
	if !ok {
		v.logger.Error().Msg("failed to get userID from context")
		return ctx.Status(fiber.StatusInternalServerError).SendString("error getting userID from context")
	}
	return ctx.SendString(fmt.Sprintf("logged in user %s", userID))
}
