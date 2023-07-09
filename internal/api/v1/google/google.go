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

package google

import (
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/api/v1/options"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/sessionKind"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
)

type Google struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Google {
	l := logger.With().Str("ROUTER", "GOOGLE").Logger()
	i := &Google{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *Google) init() {
	a.logger.Debug().Msg("initializing")
	a.app.Get("/login", a.GoogleLogin)
	a.app.Get("/callback", a.GoogleCallback)
}

func (a *Google) App() *fiber.App {
	return a.app
}

// GoogleLogin godoc
// @Summary      GoogleLogin logs in a user with Google
// @Description  GoogleLogin logs in a user with Google
// @Tags         google, login
// @Accept       json
// @Produce      json
// @Param        next         query string false "Next Redirect URL"
// @Param        organization query string false "Organization"
// @Param        identifier   query string false "Device Flow Identifier"
// @Success      307
// @Header       307 {string} Location "Redirects to Google"
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /google/login [get]
func (a *Google) GoogleLogin(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GoogleLogin from %s", ctx.IP())
	if a.options.GoogleProvider() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("google provider is not enabled")
	}

	identifier := ctx.Query("identifier")
	if identifier != "" {
		if a.options.DeviceProvider() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}

		exists, err := a.options.DeviceProvider().FlowExists(ctx.Context(), identifier)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to check if device flow exists")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if device flow exists")
		}

		if !exists {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid device flow identifier")
		}
	}

	redirect, err := a.options.GoogleProvider().StartFlow(ctx.Context(), ctx.Query("next", a.options.DefaultNextURL()), ctx.Query("organization"), identifier)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get redirect")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get redirect")
	}
	return ctx.Redirect(redirect, fiber.StatusTemporaryRedirect)
}

// GoogleCallback godoc
// @Summary      GoogleCallback logs in a user with Google
// @Description  GoogleCallback logs in a user with Google
// @Tags         google, callback
// @Accept       json
// @Produce      json
// @Success      307
// @Header       307 {string} Location "Redirects to Next URL"
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /google/callback [get]
func (a *Google) GoogleCallback(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GoogleCallback from %s", ctx.IP())
	if a.options.GoogleProvider() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("google provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusUnauthorized).SendString("code is required")
	}

	state := ctx.Query("state")
	if state == "" {
		return ctx.Status(fiber.StatusUnauthorized).SendString("state is required")
	}

	a.logger.Debug().Msgf("completing flow for state %s", state)
	email, organization, nextURL, deviceIdentifier, err := a.options.GoogleProvider().CompleteFlow(ctx.Context(), code, state)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("code is invalid")
		}
		a.logger.Error().Err(err).Msg("failed to get token")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get token")
	}

	a.logger.Debug().Msgf("creating session for user %s", email)

	kind := sessionKind.Google
	if deviceIdentifier != "" {
		if a.options.DeviceProvider() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}
		kind = sessionKind.Device
	}

	cookie, err := a.options.Controller().CreateSession(ctx, kind, a.options.GoogleProvider().Key(), email, organization)
	if cookie == nil {
		return err
	}

	if deviceIdentifier != "" {
		err = a.options.DeviceProvider().CompleteFlow(ctx.Context(), deviceIdentifier, cookie.Value, cookie.Expires)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to complete device flow")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to complete device flow")
		}
	} else {
		ctx.Cookie(cookie)
	}

	return ctx.Redirect(nextURL, fiber.StatusTemporaryRedirect)

}
