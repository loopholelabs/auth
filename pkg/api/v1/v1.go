//SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/docs"
)

//go:generate go tool github.com/swaggo/swag/cmd/swag init -g v1.go -o docs --parseDependency --instanceName AuthAPI -d ./

const (
	SessionCookie = "authentication-session"
)

type V1 struct {
	logger types.Logger
	app    *fiber.App

	options options.Options
}

func New(options options.Options, logger types.Logger) *V1 {
	v := &V1{
		logger:  logger.SubLogger("V1"),
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	v.init()

	return v
}

// @title Auth API v1
// @version 1.0
// @description Auth API, v1
// @termsOfService https://loopholelabs.io/privacy
// @contact.name API Support
// @contact.email admin@loopholelabs.io
// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @schemes https
// @BasePath /v1
func (v *V1) init() {
	v.logger.Debug().Msg("initializing")

	docs.SwaggerInfoAuthAPI.Host = v.options.Endpoint
	docs.SwaggerInfoAuthAPI.Schemes = []string{"http"}
	if v.options.TLS {
		docs.SwaggerInfoAuthAPI.Schemes = []string{"https"}
	}

	v.app.Get("/health", v.health)
	v.app.Post("/logout", v.logout)

	v.app.Get("/swagger.json", func(ctx *fiber.Ctx) error {
		ctx.Response().Header.SetContentType("application/json")
		return ctx.SendString(docs.SwaggerInfoAuthAPI.ReadDoc())
	})

	v.app.Get("/openapi.json", func(ctx *fiber.Ctx) error {
		ctx.Response().Header.SetContentType("application/json")
		return ctx.SendString(docs.SwaggerInfoAuthAPI.ReadDoc())
	})
}

func (v *V1) App() *fiber.App {
	return v.app
}

// logout godoc
// @Summary      logout logs out a user
// @Description  logout logs out a user
// @Tags         logout
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /logout [post]
func (v *V1) logout(ctx *fiber.Ctx) error {
	v.logger.Debug().Str("IP", ctx.IP()).Msg("logout")
	cookie := ctx.Cookies(SessionCookie)
	if cookie != "" {
		session, _, err := v.options.Manager.ParseSession(cookie)
		if err == nil {
			err = v.options.Manager.RevokeSession(ctx.Context(), session.Identifier)
			if err != nil {
				v.logger.Error().Err(err).Str("IP", ctx.IP()).Msg("revoking session failed")
			}
		}
		ctx.ClearCookie(SessionCookie)
	}
	return ctx.Status(fiber.StatusOK).SendString("logged out")
}

// health godoc
// @Summary      health returns the health check status
// @Description  health returns the health check status
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      500 {string} string
// @Router       /health [get]
func (v *V1) health(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusOK).SendString("OK")
}
