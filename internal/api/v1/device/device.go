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

package device

import (
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/api/v1/models"
	"github.com/loopholelabs/auth/internal/api/v1/options"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
	"time"
)

const (
	DefaultPollingRate = 5 // 5 seconds
)

type Device struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Device {
	l := logger.With().Str("ROUTER", "DEVICE").Logger()
	i := &Device{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (d *Device) init() {
	d.logger.Debug().Msg("initializing")
	d.app.Post("/flow", d.DeviceFlow)
	d.app.Post("/callback", d.DeviceCallback)
	d.app.Post("/poll", d.DevicePoll)
}

func (d *Device) App() *fiber.App {
	return d.app
}

// DeviceFlow godoc
// @Summary      DeviceFlow starts the device code flow
// @Description  DeviceFlow starts the device code flow
// @Tags         device, login
// @Accept       json
// @Produce      json
// @Success      200 {object} models.DeviceFlowResponse
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /device/flow [post]
func (d *Device) DeviceFlow(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received DeviceFlow from %s", ctx.IP())
	if d.options.DeviceProvider() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device code provider is not enabled")
	}

	deviceCode, userCode, err := d.options.DeviceProvider().StartFlow(ctx.Context())
	if err != nil {
		d.logger.Error().Err(err).Msg("failed to get device code and user code")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get device code and user code")
	}

	return ctx.JSON(&models.DeviceFlowResponse{
		DeviceCode:  deviceCode,
		UserCode:    userCode,
		PollingRate: DefaultPollingRate,
	})
}

// DeviceCallback godoc
// @Summary      DeviceCallback validates the device code and returns the flow identifier
// @Description  DeviceCallback validates the device code and returns the flow identifier
// @Tags         device, callback
// @Accept       json
// @Produce      json
// @Param        code query string true "device code"
// @Success      200 {object} models.DeviceCallbackResponse
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /device/callback [post]
func (d *Device) DeviceCallback(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received DeviceCallback from %s", ctx.IP())
	if d.options.DeviceProvider() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device code provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("code is required")
	}

	identifier, err := d.options.DeviceProvider().ValidateFlow(ctx.Context(), code)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid code")
		}
		d.logger.Error().Err(err).Msg("failed to validate device code")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to validate device code")
	}

	return ctx.JSON(&models.DeviceCallbackResponse{
		Identifier: identifier,
	})
}

// DevicePoll godoc
// @Summary      DevicePoll polls the device code flow using the user code
// @Description  DevicePoll polls the device code flow using the user code
// @Tags         device, poll
// @Accept       json
// @Produce      json
// @Param        code query string true "user code"
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      403 {string} string
// @Failure      429 {string} string
// @Failure      500 {string} string
// @Router       /device/poll [post]
func (d *Device) DevicePoll(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received DevicePoll from %s", ctx.IP())
	if d.options.DeviceProvider() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device code provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("code is required")
	}

	session, expires, lastPoll, err := d.options.DeviceProvider().PollFlow(ctx.Context(), code)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid code")
		}
		d.logger.Error().Err(err).Msg("failed to poll device code")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to poll device code")
	}

	if lastPoll.Add(DefaultPollingRate * time.Second).After(time.Now()) {
		return ctx.Status(fiber.StatusTooManyRequests).SendString("polling rate exceeded")
	}

	if session != "" {
		if expires.Before(time.Now()) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("code expired")
		}

		ctx.Cookie(d.options.Controller().GenerateCookie(session, expires))

		return ctx.SendString("success")
	}

	return ctx.Status(fiber.StatusForbidden).SendString("code not yet authorized")
}
