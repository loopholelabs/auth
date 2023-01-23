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

package github

import (
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/ent"
	"github.com/loopholelabs/auth/pkg/api/v1/options"
	"github.com/loopholelabs/auth/pkg/kind"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
)

type Github struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Github {
	l := logger.With().Str("ROUTER", "GITHUB").Logger()
	i := &Github{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *Github) init() {
	a.logger.Debug().Msg("initializing")
	a.app.Get("/login", a.GithubLogin)
	a.app.Get("/callback", a.GithubCallback)
}

func (a *Github) App() *fiber.App {
	return a.app
}

// GithubLogin godoc
// @Summary      GithubLogin logs in a user with Github
// @Description  GithubLogin logs in a user with Github
// @Tags         github, login
// @Accept       json
// @Produce      json
// @Param        next         query string false "Next Redirect URL"
// @Param        organization query string false "Organization"
// @Param        identifier   query string false "Device Flow Identifier"
// @Success      307
// @Header       307 {string} Location "Redirects to Github"
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /github/login [get]
func (a *Github) GithubLogin(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GithubLogin from %s", ctx.IP())
	if a.options.Github() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("github provider is not enabled")
	}

	identifier := ctx.Query("identifier")
	if identifier != "" {
		if a.options.Device() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}

		exists, err := a.options.Device().FlowExists(ctx.Context(), identifier)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to check if device flow exists")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if device flow exists")
		}

		if !exists {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid device flow identifier")
		}
	}

	redirect, err := a.options.Github().StartFlow(ctx.Context(), ctx.Query("next", a.options.NextURL()), ctx.Query("organization"), identifier)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get redirect")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get redirect")
	}
	return ctx.Redirect(redirect, fiber.StatusTemporaryRedirect)
}

// GithubCallback godoc
// @Summary      GithubCallback logs in a user with Github
// @Description  GithubCallback logs in a user with Github
// @Tags         github, callback
// @Accept       json
// @Produce      json
// @Success      307
// @Header       307 {string} Location "Redirects to Next URL"
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /github/callback [get]
func (a *Github) GithubCallback(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GithubCallback from %s", ctx.IP())
	if a.options.Github() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("github provider is not enabled")
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
	userID, organization, nextURL, deviceIdentifier, err := a.options.Github().CompleteFlow(ctx.Context(), code, state)
	if err != nil {
		if ent.IsNotFound(err) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("code is invalid")
		}
		a.logger.Error().Err(err).Msg("failed to get token")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get token")
	}

	a.logger.Debug().Msgf("creating session for user %s", userID)

	sessionKind := kind.Default
	if deviceIdentifier != "" {
		if a.options.Device() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}
		sessionKind = kind.Device
	}

	cookie, err := a.options.Manager().CreateSession(ctx, sessionKind, a.options.Github().Key(), userID, organization)
	if cookie == nil {
		return err
	}

	if deviceIdentifier != "" {
		err = a.options.Device().CompleteFlow(ctx.Context(), deviceIdentifier, cookie.Value, cookie.Expires)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to complete device flow")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to complete device flow")
		}
	} else {
		ctx.Cookie(cookie)
	}

	return ctx.Redirect(nextURL, fiber.StatusTemporaryRedirect)

}
