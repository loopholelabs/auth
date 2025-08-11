//SPDX-License-Identifier: Apache-2.0

package user

import (
	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
)

type User struct {
	logger types.Logger
	app    *fiber.App

	options options.Options
}

func New(options options.Options, logger types.Logger) *User {
	a := &User{
		logger:  logger.SubLogger("USER"),
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	a.app.Get("/info", a.info)

	return a
}

func (a *User) App() *fiber.App {
	return a.app
}

// info godoc
// @Summary      info returns the information about a logged-in User
// @Description  info returns the information about a logged-in User
// @Tags         user, info
// @Accept       json
// @Produce      json
// @Success      307
// @Header       307 {string} Location "Redirects to User"
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      404 {string} string
// @Failure      500 {string} string
// @Router       /flows/github/info [get]
func (a *User) info(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IP", ctx.IP()).Msg("info")
	//if a.options.Manager.User() == nil {
	//	return ctx.Status(fiber.StatusUnauthorized).SendString("github provider is not enabled")
	//}
	//
	//nextURL := ctx.Query("next")
	//if nextURL == "" {
	//	return ctx.Status(fiber.StatusBadRequest).SendString("next URL is required")
	//}
	//
	//var err error
	//var deviceIdentifier string
	//code := ctx.Query("code")
	//if code != "" && len(code) == 8 {
	//	if a.options.Manager.Device() == nil {
	//		return ctx.Status(fiber.StatusUnauthorized).SendString("device provider is not enabled")
	//	}
	//	deviceIdentifier, err = a.options.Manager.Device().ExistsFlow(ctx.Context(), code)
	//	if err != nil {
	//		a.logger.Error().Err(err).Msg("error checking if flow exists")
	//		return ctx.SendStatus(fiber.StatusInternalServerError)
	//	}
	//	if deviceIdentifier == "" {
	//		return ctx.Status(fiber.StatusNotFound).SendString("device flow does not exist")
	//	}
	//}
	//
	//redirect, err := a.options.Manager.User().CreateFlow(ctx.Context(), deviceIdentifier, "", nextURL)
	//if err != nil {
	//	a.logger.Error().Err(err).Msg("failed to get redirect")
	//	return ctx.SendStatus(fiber.StatusInternalServerError)
	//}
	return ctx.SendStatus(fiber.StatusUnauthorized)
}
