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
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/ent"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/api/v1/options"
	"github.com/loopholelabs/auth/pkg/utils"
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
	d.app.Get("/flow", d.DeviceFlow)
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
// @Success      200 {object} models.GetDeviceFlowResponse
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /device/flow [get]
func (d *Device) DeviceFlow(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received DeviceFlow from %s", ctx.IP())
	if d.options.Device() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device code provider is not enabled")
	}

	deviceCode, userCode, err := d.options.Device().StartFlow(ctx.Context())
	if err != nil {
		d.logger.Error().Err(err).Msg("failed to get device code and user code")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to get device code and user code")
	}

	return ctx.JSON(&models.GetDeviceFlowResponse{
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
// @Success      200 {object} models.GetDeviceCallbackResponse
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /device/callback [post]
func (d *Device) DeviceCallback(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received DeviceCallback from %s", ctx.IP())
	if d.options.Device() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device code provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("code is required")
	}

	identifier, err := d.options.Device().ValidateFlow(ctx.Context(), code)
	if err != nil {
		if ent.IsNotFound(err) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid code")
		}
		d.logger.Error().Err(err).Msg("failed to validate device code")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to validate device code")
	}

	return ctx.JSON(&models.GetDeviceCallbackResponse{
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
// @Failure      500 {string} string
// @Router       /device/poll [post]
func (d *Device) DevicePoll(ctx *fiber.Ctx) error {
	d.logger.Debug().Msgf("received DevicePoll from %s", ctx.IP())
	if d.options.Device() == nil {
		return ctx.Status(fiber.StatusUnauthorized).SendString("device code provider is not enabled")
	}

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).SendString("code is required")
	}

	session, expires, lastPoll, err := d.options.Device().PollFlow(ctx.Context(), code)
	if err != nil {
		if ent.IsNotFound(err) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid code")
		}
		d.logger.Error().Err(err).Msg("failed to poll device code")
		return ctx.Status(fiber.StatusInternalServerError).SendString("failed to poll device code")
	}

	if lastPoll.Add(DefaultPollingRate * time.Second).Before(time.Now()) {
		return ctx.Status(fiber.StatusUnauthorized).SendString("polling rate exceeded")
	}

	if expires.Before(time.Now()) {
		return ctx.Status(fiber.StatusUnauthorized).SendString("code expired")
	}

	ctx.Cookie(d.options.Manager().GenerateCookie(session, expires))

	return ctx.SendString("success")
}