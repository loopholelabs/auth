//SPDX-License-Identifier: Apache-2.0

package magic

import (
	"database/sql"
	"errors"
	"net/url"

	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/mailer"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
)

type Magic struct {
	logger types.Logger
	app    *fiber.App

	emailVerifier *emailverifier.Verifier

	options options.Options
}

func New(options options.Options, logger types.Logger) *Magic {
	a := &Magic{
		logger:        logger.SubLogger("MAGIC"),
		app:           utils.DefaultFiberApp(),
		emailVerifier: emailverifier.NewVerifier(),
		options:       options,
	}

	a.app.Get("/login", a.login)
	a.app.Get("/callback", a.callback)

	return a
}

func (a *Magic) App() *fiber.App {
	return a.app
}

// login godoc
// @Summary      login logs in a user with a Magic Link
// @Description  login logs in a user with a Magic Link
// @Tags         magic, login
// @Accept       json
// @Produce      json
// @Param        email        query string true  "Email Address"
// @Param        next         query string true  "Next Redirect URL"
// @Param        code         query string false "Device Flow Code"
// @Success      307
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /flows/magic/login [get]
func (a *Magic) login(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("login")
	if a.options.Manager.Magic() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("magic provider is not enabled")
	}

	if a.options.Manager.Mailer() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("email provider is not enabled")
	}

	nextURL := ctx.Query("next")
	if nextURL == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("next URL is required")
	}

	email := ctx.Query("email")
	if email == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("email is required")
	}

	ret, err := a.emailVerifier.Verify(email)
	if err != nil || !ret.Syntax.Valid || !ret.HasMxRecords {
		return ctx.Status(fiber.StatusBadRequest).SendString("invalid email address")
	}

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

	token, err := a.options.Manager.Magic().CreateFlow(ctx.Context(), email, deviceIdentifier, "", nextURL)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get token")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}

	var callback url.URL
	callback.Scheme = "http"
	if a.options.TLS {
		callback.Scheme = "https"
	}
	callback.Host = a.options.Endpoint
	callback.Path = "/v1/flows/magic/callback"
	callback.Query().Add("token", token)

	err = a.options.Manager.Mailer().SendMagicLink(ctx.Context(), mailer.Email{
		To: email,
	}, callback.String(), magic.Expiry)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to send magic link")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}

	return ctx.SendStatus(fiber.StatusOK)
}

// callback godoc
// @Summary      callback logs in a user with a Magic Link
// @Description  callback logs in a user with a Magic Link
// @Tags         magic, callback
// @Accept       json
// @Produce      json
// @Param        token        query string true "magic link token"
// @Success      307
// @Header       307 {string} Location "Redirects to Next URL"
// @Header       307 {string} Set-Cookie "authentication_session=jwt_token; HttpOnly; SameSite=lax;"
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /flows/magic/callback [get]
func (a *Magic) callback(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("callback")
	if a.options.Manager.Magic() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("magic provider is not enabled")
	}

	token := ctx.Query("token")
	if token == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("token is required")
	}

	f, err := a.options.Manager.Magic().CompleteFlow(ctx.Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ctx.Status(fiber.StatusNotFound).SendString("flow does not exist")
		case errors.Is(err, magic.ErrInvalidToken):
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid token")
		default:
			a.logger.Error().Err(err).Msg("failed to complete flow")
			return ctx.SendStatus(fiber.StatusInternalServerError)
		}
	}

	if f.DeviceIdentifier != "" {
		if a.options.Manager.Device() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}
	}

	session, err := a.options.Manager.CreateSession(ctx.Context(), f, flow.MagicProvider)
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
		signedToken, err := a.options.Manager.SignSession(session)
		if err != nil {
			a.logger.Error().Err(err).Msg("error signing session")
			return ctx.SendStatus(fiber.StatusInternalServerError)
		}

		cookie := &fiber.Cookie{
			Name:     models.SessionCookie,
			Value:    signedToken,
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
