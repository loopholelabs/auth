//SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"
	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/flows"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
)

// SessionCookie is now in models package

type V1 struct {
	logger types.Logger
	app    *fiber.App
	api    huma.API

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

func (v *V1) init() {
	v.logger.Debug().Msg("initializing")

	// Configure Huma API
	config := huma.DefaultConfig("Auth API v1", "1.0")
	config.DocsPath = ""
	config.Info.Description = "Authentication API, v1"
	config.Info.TermsOfService = "https://loopholelabs.io/privacy"
	config.Info.Contact = &huma.Contact{
		Name:  "API Support",
		Email: "admin@loopholelabs.io",
	}
	config.Info.License = &huma.License{
		Name: "Apache 2.0",
		URL:  "https://www.apache.org/licenses/LICENSE-2.0.html",
	}

	// Configure servers
	scheme := "http"
	if v.options.TLS {
		scheme = "https"
	}
	config.Servers = []*huma.Server{
		{
			URL: fmt.Sprintf("%s://%s/v1", scheme, v.options.Endpoint),
		},
	}

	// Configure security schemes
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"cookieAuth": {
			Type:        "apiKey",
			In:          "cookie",
			Name:        models.SessionCookie,
			Description: "User Session Cookie",
		},
	}

	// Create Huma API with Fiber adapter
	v.api = humafiber.New(v.app, config)

	// Register core endpoints
	v.registerCoreEndpoints()

	// Register flow endpoints
	flows.RegisterEndpoints(v.api, v.options, v.logger)
}

func (v *V1) registerCoreEndpoints() {
	// Health endpoint
	huma.Register(v.api, huma.Operation{
		OperationID: "health",
		Method:      "GET",
		Path:        "/health",
		Summary:     "Health check",
		Description: "Returns the health check status",
		Tags:        []string{"health"},
	}, v.health)

	// Public endpoint
	huma.Register(v.api, huma.Operation{
		OperationID: "public",
		Method:      "GET",
		Path:        "/public",
		Summary:     "Get public keys and session information",
		Description: "Returns the current public key and session information",
		Tags:        []string{"public"},
	}, v.public)

	// Logout endpoint
	huma.Register(v.api, huma.Operation{
		OperationID: "logout",
		Method:      "POST",
		Path:        "/logout",
		Summary:     "Logout user",
		Description: "Logs out a user by revoking their session",
		Tags:        []string{"logout"},
	}, v.logout)

	v.app.Get("/docs", v.docs)
}

func (v *V1) App() *fiber.App {
	return v.app
}

func (v *V1) docs(ctx *fiber.Ctx) error {
	ctx.Set("content-type", "text/html; charset=utf-8")
	return ctx.SendString(`<!doctype html>
<html>
  <head>
    <title>API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      data-url="/v1/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`)
}

func (v *V1) health(_ context.Context, _ *struct{}) (*HealthResponse, error) {
	v.logger.Trace().Msg("health")
	if v.options.Manager.IsHealthy() && v.options.Validator.IsHealthy() {
		return &HealthResponse{StatusCode: 200}, nil
	}
	return &HealthResponse{StatusCode: 503}, nil
}

func (v *V1) public(_ context.Context, _ *struct{}) (*PublicResponse, error) {
	v.logger.Debug().Msg("public")

	publicKey := v.options.Manager.Configuration().EncodedPublicKey()
	if publicKey == nil {
		v.logger.Error().Msg("public key is nil")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	response := &PublicResponse{
		Body: PublicResponseBody{
			PublicKey:           base64.StdEncoding.EncodeToString(publicKey),
			RevokedSessions:     v.options.Validator.SessionRevocationList(),
			InvalidatedSessions: v.options.Validator.SessionInvalidationList(),
		},
	}

	previousPublicKey := v.options.Manager.Configuration().EncodedPreviousPublicKey()
	if previousPublicKey != nil {
		response.Body.PreviousPublicKey = base64.StdEncoding.EncodeToString(previousPublicKey)
	}

	return response, nil
}

func (v *V1) logout(ctx context.Context, _ *LogoutRequest) (*LogoutResponse, error) {
	v.logger.Debug().Msg("logout")

	// Extract the Fiber context to access cookies
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)

	output := &LogoutResponse{StatusCode: 200}

	cookie := fiberCtx.Cookies(models.SessionCookie)
	if cookie != "" {
		session, _, err := v.options.Manager.ParseSession(cookie)
		if err == nil {
			err = v.options.Manager.RevokeSession(ctx, session.Identifier)
			if err != nil {
				v.logger.Error().Err(err).Msg("revoking session failed")
			}
		}

		// Clear the cookie by setting it with MaxAge 0
		output.Headers.SetCookie = &http.Cookie{
			Name:     models.SessionCookie,
			Value:    "",
			MaxAge:   0,
			Path:     "/",
			Domain:   v.options.Endpoint,
			Secure:   v.options.TLS,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
	}

	return output, nil
}
