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

package magic

import (
	"errors"
	"fmt"
	"github.com/AfterShip/email-verifier"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/api/v1/options"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/flow/magic"
	"github.com/loopholelabs/auth/pkg/sessionKind"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
)

type Magic struct {
	logger   *zerolog.Logger
	app      *fiber.App
	options  *options.Options
	verifier *emailverifier.Verifier
}

func New(options *options.Options, logger *zerolog.Logger) *Magic {
	l := logger.With().Str("ROUTER", "MAGIC").Logger()
	i := &Magic{
		logger:   &l,
		app:      utils.DefaultFiberApp(),
		options:  options,
		verifier: emailverifier.NewVerifier(),
	}

	i.init()

	return i
}

func (d *Magic) init() {
	d.logger.Debug().Msg("initializing")
	d.app.Post("/flow", d.MagicFlow)
	d.app.Get("/callback", d.MagicCallback)
}

func (d *Magic) App() *fiber.App {
	return d.app
}

// MagicFlow godoc
// @Summary      MagicFlow starts the magic link flow
// @Description  MagicFlow starts the magic link flow
// @Tags         device, login
// @Accept       json
// @Produce      json
// @Param        email        query string true "email address"
// @Param        next         query string false "Next Redirect URL"
// @Param        organization query string false "Organization"
// @Param        identifier   query string false "Device Flow Identifier"
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /magic/flow [post]
func (d *Magic) MagicFlow(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received MagicFlow from %s", ctx.IP())
	if d.options.MagicProvider() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("magic link provider is not enabled")
	}

	email := ctx.Query("email")
	if email == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("email is required")
	}

	ret, err := d.verifier.Verify(email)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).SendString("invalid email address")
	}

	if !ret.Syntax.Valid || !ret.HasMxRecords {
		return ctx.Status(fiber.StatusBadRequest).SendString("invalid email address")
	}

	identifier := ctx.Query("identifier")
	if identifier != "" {
		if d.options.DeviceProvider() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}

		exists, err := d.options.DeviceProvider().FlowExists(ctx.Context(), identifier)
		if err != nil {
			d.logger.Error().Err(err).Msg("failed to check if device flow exists")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if device flow exists")
		}

		if !exists {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid device flow identifier")
		}
	}

	secret, err := d.options.MagicProvider().StartFlow(ctx.Context(), email, ctx.IP(), ctx.Query("next", d.options.DefaultNextURL()), ctx.Query("organization"), identifier)
	if err != nil {
		d.logger.Error().Err(err).Msg("failed to get device code and user code")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get device code and user code")
	}

	encoded, err := d.options.Controller().EncodeMagic(email, secret)
	if err != nil {
		d.logger.Error().Err(err).Msg("failed to encrypt magic")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to encrypt magic")
	}
	scheme := "http"
	if d.options.TLS() {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s", scheme, d.options.Endpoint())
	err = d.options.MagicProvider().SendMagic(ctx.Context(), url, email, ctx.IP(), encoded)
	if err != nil {
		d.logger.Error().Err(err).Msg("failed to send magic link")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to send magic link")
	}

	return ctx.Status(fiber.StatusOK).SendString("magic link sent")
}

// MagicCallback godoc
// @Summary      MagicCallback validates the magic link and logs in the user
// @Description  MagicCallback validates the magic link and logs in the user
// @Tags         magic, callback
// @Accept       json
// @Produce      json
// @Param        token query string true "magic link token"
// @Success      307
// @Header       307 {string} Location "Redirects to Next URL"
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /magic/callback [get]
func (d *Magic) MagicCallback(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received MagicCallback from %s", ctx.IP())
	if d.options.MagicProvider() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("magic link provider is not enabled")
	}

	encodedToken := ctx.Query("token")
	if encodedToken == "" {
		return ctx.Status(fiber.StatusUnauthorized).SendString("token is required")
	}

	email, secret, err := d.options.Controller().DecodeMagic(encodedToken)
	if err != nil {
		d.logger.Error().Err(err).Msg("failed to decrypt magic link token")
		return ctx.Status(fiber.StatusUnauthorized).SendString("invalid magic link token")
	}

	d.logger.Debug().Msgf("completing flow for %s", email)
	organization, nextURL, deviceIdentifier, err := d.options.MagicProvider().CompleteFlow(ctx.Context(), email, secret)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, magic.ErrInvalidSecret) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid magic link token")
		}
		d.logger.Error().Err(err).Msg("failed to complete magic link flow")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to complete magic link flow")
	}

	d.logger.Debug().Msgf("creating session for user %s", email)

	kind := sessionKind.Magic
	if deviceIdentifier != "" {
		if d.options.DeviceProvider() == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
		}
		kind = sessionKind.Device
	}

	cookie, err := d.options.Controller().CreateSession(ctx, kind, d.options.MagicProvider().Key(), email, organization)
	if cookie == nil {
		return err
	}

	if deviceIdentifier != "" {
		err = d.options.DeviceProvider().CompleteFlow(ctx.Context(), deviceIdentifier, cookie.Value, cookie.Expires)
		if err != nil {
			d.logger.Error().Err(err).Msg("failed to complete device flow")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to complete device flow")
		}
	} else {
		ctx.Cookie(cookie)
	}

	return ctx.Redirect(nextURL, fiber.StatusTemporaryRedirect)
}
