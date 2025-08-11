//SPDX-License-Identifier: Apache-2.0

package device

import (
	"database/sql"
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/manager/flow/device"
)

const (
	PollingRate = time.Second * 5
)

type Device struct {
	logger types.Logger
	app    *fiber.App

	options options.Options
}

func New(options options.Options, logger types.Logger) *Device {
	a := &Device{
		logger:  logger.SubLogger("DEVICE"),
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	a.app.Get("/login", a.login)
	a.app.Get("/validate", a.validate)
	a.app.Get("/poll", a.poll)

	return a
}

func (a *Device) App() *fiber.App {
	return a.app
}

// login godoc
// @Summary      login logs in a user with the Device Code Flow
// @Description  login logs in a user with the Device Code Flow
// @Tags         device, login
// @Accept       json
// @Produce      json
// @Success      200 {object} models.DeviceFlowResponse
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /flows/device/login [get]
func (a *Device) login(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("login")
	if a.options.Manager.Device() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
	}

	code, poll, err := a.options.Manager.Device().CreateFlow(ctx.Context())
	if err != nil {
		a.logger.Error().Err(err).Msg("error creating flow")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}

	return ctx.Status(fiber.StatusOK).JSON(&models.DeviceFlowResponse{
		Code:               code,
		Poll:               poll,
		PollingRateSeconds: uint64(PollingRate.Truncate(time.Second).Seconds()),
	})
}

// validate godoc
// @Summary      validate validates the code
// @Description  validate validates the code
// @Tags         device, validate
// @Accept       json
// @Produce      json
// @Param        code query string true "code"
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /flows/device/validate [get]
func (a *Device) validate(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("validate")
	if a.options.Manager.Device() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("code is required")
	}
	if len(code) != 8 {
		return ctx.Status(fiber.StatusBadRequest).SendString("invalid code")
	}

	identifier, err := a.options.Manager.Device().ExistsFlow(ctx.Context(), code)
	if err != nil {
		a.logger.Error().Err(err).Msg("error checking if flow exists")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}
	if identifier == "" {
		return ctx.Status(fiber.StatusNotFound).SendString("flow does not exist")
	}
	return ctx.SendStatus(fiber.StatusOK)
}

// poll godoc
// @Summary      poll polls the device code flow using the poll code
// @Description  poll polls the device code flow using the poll code
// @Tags         device, poll
// @Accept       json
// @Produce      json
// @Param        poll query string true "poll"
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      404 {string} string
// @Failure      429 {string} string
// @Failure      500 {string} string
// @Router       /flows/device/poll [get]
func (a *Device) poll(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("poll")
	if a.options.Manager.Device() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("code is required")
	}
	if len(code) != 36 {
		return ctx.Status(fiber.StatusBadRequest).SendString("invalid code")
	}

	sessionIdentifier, err := a.options.Manager.Device().PollFlow(ctx.Context(), code, PollingRate)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ctx.Status(fiber.StatusNotFound).SendString("flow does not exist")
		case errors.Is(err, device.ErrRateLimitFlow):
			return ctx.Status(fiber.StatusTooManyRequests).SendString("polling rate exceeded")
		case errors.Is(err, device.ErrFlowNotCompleted):
			return ctx.Status(fiber.StatusForbidden).SendString("incomplete flow")
		default:
			a.logger.Error().Err(err).Msg("error polling flow")
			return ctx.SendStatus(fiber.StatusInternalServerError)
		}
	}

	session, err := a.options.Manager.CreateExistingSession(ctx.Context(), sessionIdentifier)
	if err != nil {
		a.logger.Error().Err(err).Msg("error creating session")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}

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

	return ctx.SendStatus(fiber.StatusOK)
}
