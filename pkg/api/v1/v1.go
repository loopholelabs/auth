//SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/pkg/api/v1/flows"
	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential"
)

const (
	Path = "/v1"
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

func (v *V1) init() {
	v.logger.Debug().Msg("initializing")

	// Configure OpenAPI
	config := huma.DefaultConfig("Authentication API", "1.0")
	config.DocsPath = ""
	config.Info.Description = "Authentication API"
	config.Info.TermsOfService = "https://loopholelabs.io/privacy"
	config.Info.Contact = &huma.Contact{
		Name:  "API Support",
		Email: "admin@loopholelabs.io",
	}
	config.Info.License = &huma.License{
		Name: "Apache 2.0",
		URL:  "https://www.apache.org/licenses/LICENSE-2.0.html",
	}

	server := &url.URL{
		Scheme: "http",
		Host:   v.options.Endpoint,
		Path:   Path,
	}
	if v.options.TLS {
		server.Scheme = "https"
	}

	config.Servers = []*huma.Server{
		{
			URL: server.String(),
		},
	}

	// Configure security schemes
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"cookieAuth": {
			Type:        "apiKey",
			In:          "cookie",
			Name:        credential.SessionCookie,
			Description: "session cookie",
		},
	}

	prefixes := []string{"v1"}
	api := humafiber.New(v.app, config)

	healthPrefix := append(prefixes, "health") //nolint:gocritic
	huma.Register(api, huma.Operation{
		OperationID:   strings.Join(healthPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/health",
		Summary:       "health check",
		Description:   "returns the health check status",
		Tags:          healthPrefix,
		DefaultStatus: 200,
		Errors:        []int{503},
	}, v.health)

	publicPrefix := append(prefixes, "public") //nolint:gocritic
	huma.Register(api, huma.Operation{
		OperationID:   strings.Join(publicPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/public",
		Summary:       "get public keys and session information",
		Description:   "returns the current public key and session information",
		Tags:          publicPrefix,
		DefaultStatus: 200,
		Errors:        []int{500},
	}, v.public)

	logoutPrefix := append(prefixes, "logout") //nolint:gocritic
	huma.Register(api, huma.Operation{
		OperationID:   strings.Join(logoutPrefix, "-"),
		Method:        http.MethodPost,
		Path:          "/logout",
		Summary:       "logout user",
		Description:   "logs out a user by revoking their session",
		Tags:          logoutPrefix,
		DefaultStatus: 200,
	}, v.logout)

	flows.New(v.options, v.logger).Register(prefixes, api)
}

func (v *V1) App() *fiber.App {
	return v.app
}

func (v *V1) health(_ context.Context, _ *struct{}) (*struct{}, error) {
	v.logger.Trace().Msg("health")
	if !v.options.Manager.IsHealthy() {
		return nil, huma.Error503ServiceUnavailable("service unhealthy")
	}
	return nil, nil //nolint:nilnil
}

func (v *V1) public(_ context.Context, _ *struct{}) (*V1PublicResponse, error) {
	publicKey := v.options.Manager.Configuration().EncodedPublicKey()
	if publicKey == nil {
		v.logger.Error().Msg("public key is nil")
		return nil, huma.Error500InternalServerError("public key is nil")
	}

	response := &V1PublicResponse{
		Body: V1PublicResponseBody{
			PublicKey:           base64.StdEncoding.EncodeToString(publicKey),
			RevokedSessions:     v.options.Manager.SessionRevocationList(),
			InvalidatedSessions: v.options.Manager.SessionInvalidationList(),
		},
	}

	previousPublicKey := v.options.Manager.Configuration().EncodedPreviousPublicKey()
	if previousPublicKey != nil {
		response.Body.PreviousPublicKey = base64.StdEncoding.EncodeToString(previousPublicKey)
	}

	return response, nil
}

func (v *V1) logout(ctx context.Context, input *V1LogoutRequest) (*V1LogoutResponse, error) {
	response := &V1LogoutResponse{}

	// Try to get cookie from Fiber context if available
	if input.Cookie != "" {
		session, _, err := v.options.Manager.ParseSession(input.Cookie)
		if err == nil {
			err = v.options.Manager.RevokeSession(ctx, session.Identifier)
			if err != nil {
				v.logger.Error().Err(err).Msg("revoking session failed")
			}
		}

		// Clear the cookie by setting it with MaxAge 0
		response.Headers.SetCookie = &http.Cookie{
			Name:     credential.SessionCookie,
			Value:    "",
			MaxAge:   0,
			Path:     "/",
			Domain:   v.options.Endpoint,
			Secure:   v.options.TLS,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
	}

	return response, nil
}
