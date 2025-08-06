//SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/v1/docs"
)

//go:generate go tool github.com/swaggo/swag/cmd/swag init -g v1.go -o docs --parseDependency --instanceName AuthAPI -d ./

type Options struct {
	ListenAddress  string
	Endpoint       string
	TLS            bool
	DefaultNextURL string
}

type V1 struct {
	logger types.Logger
	app    *fiber.App
}

func New(logger types.Logger) *V1 {
	v := &V1{
		logger: logger.SubLogger("v1"),
		app:    utils.DefaultFiberApp(),
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

	v.app.Get("/health", v.Health)
	v.app.Post("/logout", v.Logout)

	v.app.Get("/swagger.json", func(ctx *fiber.Ctx) error {
		ctx.Response().Header.SetContentType("application/json")
		return ctx.SendString(docs.SwaggerInfoAuthAPI.ReadDoc())
	})
}

func (v *V1) App() *fiber.App {
	return v.app
}

// Logout godoc
// @Summary      Logout logs out a user
// @Description  Logout logs out a user
// @Tags         logout
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /logout [post]
func (v *V1) Logout(ctx *fiber.Ctx) error {
	v.logger.Debug().Str("IP", ctx.IP()).Msg("Logout")
	return ctx.Status(fiber.StatusOK).SendString("logged out")
}

// Health godoc
// @Summary      Health returns the health check status
// @Description  Health returns the health check status
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      500 {string} string
// @Router       /health [get]
func (v *V1) Health(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusOK).SendString("OK")
}
