//SPDX-License-Identifier: Apache-2.0

package google

import (
	"database/sql"
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/manager/flow"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
)

type Google struct {
	logger types.Logger
	app    *fiber.App

	options options.Options
}

func New(options options.Options, logger types.Logger) *Google {
	a := &Google{
		logger:  logger.SubLogger("GOOGLE"),
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	a.app.Get("/login", a.login)
	a.app.Get("/callback", a.callback)

	return a
}

func (a *Google) App() *fiber.App {
	return a.app
}

// login godoc
// @Summary      login logs in a user with Google
// @Description  login logs in a user with Google
// @Tags         google, login
// @Accept       json
// @Produce      json
// @Param        next         query string true  "Next Redirect URL"
// @Param        code         query string false "Device Flow Code"
// @Success      307
// @Header       307 {string} Location "Redirects to Google"
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /flows/google/login [get]
func (a *Google) login(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("login")
	if a.options.Manager.Google() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("google provider is not enabled")
	}

	nextURL := ctx.Query("next")
	if nextURL == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("next URL is required")
	}

	var err error
	var deviceIdentifier string
	code := ctx.Query("code")
	if code != "" && len(code) == 8 {
		if a.options.Manager.Device() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}
		deviceIdentifier, err = a.options.Manager.Device().ExistsFlow(ctx.Context(), code)
		if err != nil {
			a.logger.Error().Err(err).Msg("error checking if flow exists")
			return ctx.SendStatus(fiber.StatusInternalServerError)
		}
		if deviceIdentifier == "" {
			return ctx.Status(fiber.StatusNotFound).SendString("device flow does not exist")
		}
	}

	redirect, err := a.options.Manager.Google().CreateFlow(ctx.Context(), deviceIdentifier, "", nextURL)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get redirect")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}
	return ctx.Redirect(redirect, fiber.StatusTemporaryRedirect)
}

// callback godoc
// @Summary      callback logs in a user with Google
// @Description  callback logs in a user with Google
// @Tags         google, callback
// @Accept       json
// @Produce      json
// @Param        code         query string false "Next Redirect URL"
// @Param        state        query string false "Device Flow Code"
// @Success      307
// @Header       307 {string} Location "Redirects to Next URL"
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /flows/google/callback [get]
func (a *Google) callback(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("callback")
	if a.options.Manager.Google() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("google provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("code is required")
	}

	identifier := ctx.Query("state")
	if identifier == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("state is required")
	}

	f, err := a.options.Manager.Google().CompleteFlow(ctx.Context(), identifier, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ctx.Status(fiber.StatusNotFound).SendString("flow does not exist")
		}
		a.logger.Error().Err(err).Msg("failed to complete flow")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}

	if f.DeviceIdentifier != "" {
		if a.options.Manager.Device() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}
	}

	session, err := a.options.Manager.CreateSession(ctx.Context(), f, flow.GoogleProvider)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to create session")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}

	if f.DeviceIdentifier != "" {
		err = a.options.Manager.Device().CompleteFlow(ctx.Context(), f.DeviceIdentifier, session.Identifier)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to complete flow")
			return ctx.SendStatus(fiber.StatusInternalServerError)
		}
	} else {
		token, err := a.options.Manager.SignSession(session)
		if err != nil {
			a.logger.Error().Err(err).Msg("error signing session")
			return ctx.SendStatus(fiber.StatusInternalServerError)
		}

		cookie := &fiber.Cookie{
			Name:     models.SessionCookie,
			Value:    token,
			Expires:  session.ExpiresAt,
			Domain:   a.options.Endpoint,
			Secure:   false,
			HTTPOnly: true,
			SameSite: fiber.CookieSameSiteLaxMode,
		}
		if a.options.TLS {
			cookie.Secure = true
		}
		ctx.Cookie(cookie)
	}

	return ctx.Redirect(f.NextURL, fiber.StatusTemporaryRedirect)
}
