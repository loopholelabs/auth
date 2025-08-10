//SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/base64"

	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/docs"
	"github.com/loopholelabs/auth/pkg/api/v1/flows"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
)

//go:generate go tool github.com/swaggo/swag/cmd/swag init -g v1.go -o docs --parseDependency --instanceName AuthAPI -d ./

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

	v.app.Get("/public", v.public)
	v.app.Post("/logout", v.logout)
	v.app.Get("/health", v.health)

	v.app.Get("/swagger.json", func(ctx *fiber.Ctx) error {
		ctx.Response().Header.SetContentType("application/json")
		return ctx.SendString(docs.SwaggerInfoAuthAPI.ReadDoc())
	})

	v.app.Get("/openapi.json", func(ctx *fiber.Ctx) error {
		ctx.Response().Header.SetContentType("application/json")
		return ctx.SendString(docs.SwaggerInfoAuthAPI.ReadDoc())
	})

	v.app.Mount("/flows", flows.New(v.options, v.logger).App())
}

func (v *V1) App() *fiber.App {
	return v.app
}

// public godoc
// @Summary      public returns the current public key
// @Description  public returns the current public ket
// @Tags         public
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      400 {string} string
// @Failure      401 {string} string
// @Failure      500 {string} string
// @Router       /public [get]
func (v *V1) public(ctx *fiber.Ctx) error {
	v.logger.Debug().Str("IP", ctx.IP()).Msg("public")
	_, publicKey := v.options.Manager.Configuration().SigningKey()
	if publicKey == nil {
		v.logger.Error().Msg("public key is nil")
		return ctx.SendStatus(fiber.StatusInternalServerError)
	}
	encodedPublicKey := utils.EncodePublicKey(publicKey)

	return ctx.Status(fiber.StatusOK).JSON(&models.PublicResponse{Key: base64.StdEncoding.EncodeToString(encodedPublicKey)})
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
	cookie := ctx.Cookies(models.SessionCookie)
	if cookie != "" {
		session, _, err := v.options.Manager.ParseSession(cookie)
		if err == nil {
			err = v.options.Manager.RevokeSession(ctx.Context(), session.Identifier)
			if err != nil {
				v.logger.Error().Err(err).Str("IP", ctx.IP()).Msg("revoking session failed")
			}
		}
		ctx.ClearCookie(models.SessionCookie)
	}
	return ctx.SendStatus(fiber.StatusOK)
}

// health godoc
// @Summary      health returns the health check status
// @Description  health returns the health check status
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200 {string} string
// @Failure      503 {string} string
// @Router       /health [get]
func (v *V1) health(ctx *fiber.Ctx) error {
	v.logger.Trace().Str("IP", ctx.IP()).Msg("health")
	if v.options.Manager.Healthy() {
		return ctx.SendStatus(fiber.StatusOK)
	}
	return ctx.SendStatus(fiber.StatusServiceUnavailable)
}
