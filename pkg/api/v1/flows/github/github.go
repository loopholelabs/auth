//SPDX-License-Identifier: Apache-2.0

package github

import (
	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
)

type Github struct {
	logger types.Logger
	app    *fiber.App
}

func New(logger types.Logger) *Github {
	i := &Github{
		logger: logger.SubLogger("GITHUB"),
		app:    utils.DefaultFiberApp(),
	}

	i.app.Get("/login", i.login)

	return i
}

func (a *Github) App() *fiber.App {
	return a.app
}

// login godoc
// @Summary      Login logs in a user with Github
// @Description  Login logs in a user with Github
// @Tags         github, login
// @Accept       json
// @Produce      json
// @Param        device       query string false "Device Flow Identifier"
// @Param        next         query string false "Next Redirect URL"
// @Success      307
// @Header       307 {string} location "Redirects to Github"
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /github/login [get]
func (a *Github) login(ctx *fiber.Ctx) error {
	a.logger.Debug().Str("IPAddress", ctx.IP()).Msg("login")
	return ctx.Redirect("", fiber.StatusTemporaryRedirect)
}
