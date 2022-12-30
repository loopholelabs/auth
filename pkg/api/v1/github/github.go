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

package github

import (
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/pkg/api/v1/options"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
)

type Github struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Github {
	l := logger.With().Str("COMPONENT", "GITHUB").Logger()
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
	a.app.Post("/login", a.GithubLogin)
	a.app.Post("/login/:organization", a.GithubLoginOrganization)
	a.app.Post("/callback", a.GithubCallback)
}

func (a *Github) App() *fiber.App {
	return a.app
}

// GithubLogin godoc
// @Summary      GithubLogin logs in a user with Github
// @Description  GithubLogin logs in a user with Github
// @Tags         login, github
// @Accept       json
// @Produce      json
// @Param        organization path string true "API Key Name"
// @Success      307
// @Header       307 {string} Location "Redirects to Github"
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /github/login [post]
func (a *Github) GithubLogin(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GithubLogin from %s", ctx.IP())
	if a.options.Github() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("github provider is not enabled")
	}
	redirect, err := a.options.Github().AuthURL(ctx.Context(), "")
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get redirect")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get redirect")
	}
	return ctx.Redirect(redirect, fiber.StatusTemporaryRedirect)
}

// GithubLoginOrganization godoc
// @Summary      GithubLoginOrganization logs in a user with Github using a specific organization
// @Description  GithubLoginOrganization logs in a user with Github using a specific organization
// @Tags         login, github
// @Accept       json
// @Produce      json
// @Param        organization path string true "Organization"
// @Success      307
// @Header       307 {string} Location "Redirects to Github"
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /github/login/{organization} [post]
func (a *Github) GithubLoginOrganization(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GithubLoginOrganization from %s", ctx.IP())
	if a.options.Github() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("github provider is not enabled")
	}

	organization := ctx.Params("organization")
	if organization == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("organization is required")
	}

	redirect, err := a.options.Github().AuthURL(ctx.Context(), organization)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get redirect")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get redirect")
	}
	return ctx.Redirect(redirect, fiber.StatusTemporaryRedirect)
}

// GithubCallback godoc
// @Summary      GithubCallback logs in a user with Github
// @Description  GithubCallback logs in a user with Github
// @Tags         login, callback, github
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /github/callback [post]
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

	userID, organization, err := a.options.Github().GetUser(ctx.Context(), code, state)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get token")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get token")
	}

	complete, err := a.options.Manager().Session(ctx, a.options.Github().Key(), userID, organization)
	if !complete {
		return err
	}

	return ctx.Status(fiber.StatusOK).SendString("login successful")
}
