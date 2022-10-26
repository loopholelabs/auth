/*
	Copyright 2022 Loophole Labs

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

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dexidp/dex/connector/github"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/server"
	dexStorage "github.com/dexidp/dex/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/pkg/healthcheck"
	"github.com/loopholelabs/auth/pkg/keyset"
	"github.com/loopholelabs/auth/pkg/options"
	"github.com/loopholelabs/auth/pkg/providers"
	"github.com/loopholelabs/auth/pkg/refreshpolicy"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/auth/pkg/token"
	"github.com/loopholelabs/auth/pkg/token/identity"
	"github.com/loopholelabs/auth/pkg/token/tokenKind"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"time"
)

const (
	githubID = "github"
)

const (
	DefaultConnectorName = "Basic-Authentication"
)

var (
	InvalidConnectorError = errors.New("invalid connector configuration")
)

type Server struct {
	logger  log.Logger
	storage storage.Storage

	app         *fiber.App
	server      *server.Server
	options     *options.Options
	publicKeys  *keyset.Public
	privateKeys *keyset.Private
}

func New(options *options.Options) (*Server, error) {
	err := options.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid options for auth server: %w", err)
	}

	refreshPolicy, err := dex.DefaultRefreshPolicy(options.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create default refresh policy: %w", err)
	}

	s := &Server{
		app: fiber.New(fiber.Config{
			DisableStartupMessage: true,
			ReadTimeout:           time.Second * 5,
			WriteTimeout:          time.Second * 5,
			IdleTimeout:           time.Second * 5,
			JSONEncoder:           json.Marshal,
			JSONDecoder:           json.Unmarshal,
		}),
		logger:      options.Logger,
		storage:     options.Storage,
		options:     options,
		publicKeys:  keyset.NewPublic(options.Storage),
		privateKeys: keyset.NewPrivate(options.Storage),
	}

	return s, s.setupDex(refreshPolicy)
}

func (s *Server) App() *fiber.App {
	return s.app
}

func (s *Server) createDex(refreshPolicy *server.RefreshTokenPolicy) (*server.Server, error) {
	return server.NewServer(context.Background(), server.Config{
		Issuer:                 s.options.Issuer,
		Storage:                s.storage,
		SupportedResponseTypes: []string{"code"},
		RefreshTokenPolicy:     refreshPolicy,
		AllowedOrigins:         s.options.AllowedOrigins,
		AlwaysShowLoginScreen:  false,
		SkipApprovalScreen:     true,
		Web:                    *s.options.WebConfig,
		Logger:                 s.options.Logger,
		HealthChecker:          healthcheck.NewNoop(),
	})
}

func (s *Server) setupDex(refreshPolicy *server.RefreshTokenPolicy) error {
	d, err := s.createDex(refreshPolicy)
	if err != nil {
		return fmt.Errorf("failed to create dex server: %w", err)
	}

	s.server = d

	passThrough := passthrough(fasthttpadaptor.NewFastHTTPHandler(http.HandlerFunc(s.server.ServeHTTP)))
	customClaims := s.customClaims(passThrough)

	enabled := func(ctx *fiber.Ctx) error {
		if !s.options.Enabled() {
			return fiber.NewError(fiber.StatusForbidden, "identity service is disabled")
		}
		return ctx.Next()
	}

	s.app.Post("/exchange", s.exchange)
	s.app.Post("/refresh", s.refresh)
	s.app.All("/token", enabled, customClaims)
	s.app.All("/*", enabled, passThrough)

	return nil
}

func (s *Server) githubProviderID(name string) string {
	return fmt.Sprintf("github-%s", name)
}

// Exchange godoc
// @Summary      Exchange API Key or Service Key for a JWT and a Refresh Token
// @Description  Exchange API Key or Service Key for a JWT and a Refresh Token
// @Tags         auth
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        kind formData string  true  "Key Kind"
// @Param        key formData string  true  "Key Value"
// @Success      200  {object} ExchangeResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      500  {string} string
// @Router       /exchange [post]
func (s *Server) exchange(ctx *fiber.Ctx) error {
	if string(ctx.Request().Header.ContentType()) == fiber.MIMEApplicationForm {
		kind := ctx.FormValue("kind")
		if kind == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "kind is required")
		}

		key := ctx.FormValue("key")
		if len(key) != 73 {
			return fiber.NewError(fiber.StatusUnauthorized, "key is required")
		}

		tokenIdentifier, tokenSecret, err := token.Decode(key)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid key")
		}

		switch tokenKind.Kind(kind) {
		case tokenKind.APITokenKind:
			apiKey, err := s.storage.GetAPIKey(tokenIdentifier)
			if err != nil {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid API Key")
			}
			if !token.Verify(tokenSecret, apiKey.Secret) {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid API Key")
			}
			apiToken := token.NewAPIToken(s.options.Issuer, apiKey, identity.MachineAudiences)
			refreshToken := token.NewRefreshTokenForAPIKey(s.options.Issuer, apiKey, identity.MachineAudiences)

			signedAPIToken, err := apiToken.Sign(s.privateKeys, jose.RS256)
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, err.Error())
			}
			signedRefreshToken, err := refreshToken.Sign(s.privateKeys, jose.RS256)
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, err.Error())
			}

			return ctx.JSON(ExchangeResponse{
				AccessToken:  signedAPIToken,
				TokenType:    "Bearer",
				ExpiresIn:    int((time.Minute * 5).Seconds()),
				RefreshToken: signedRefreshToken,
			})
		case tokenKind.ServiceTokenKind:
			valid := func(key *storage.ServiceKey) error {
				if key.Expires > 0 && utils.Int64ToTime(key.Expires).Before(time.Now()) {
					return errors.New("service key has expired")
				}
				if key.MaxUses > 0 && key.NumUsed >= key.MaxUses {
					return errors.New("service key has reached max uses")
				}
				if !token.Verify(tokenSecret, key.Secret) {
					return errors.New("invalid service key")
				}

				return nil
			}

			update := func(key *storage.ServiceKey) {
				key.NumUsed++
			}

			serviceKey, err := s.storage.GetServiceKey(tokenIdentifier, valid, update)
			if err != nil {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid Service Key")
			}

			serviceToken := token.NewServiceToken(s.options.Issuer, serviceKey, identity.MachineAudiences)
			refreshToken := token.NewRefreshTokenForServiceKey(s.options.Issuer, serviceKey, identity.MachineAudiences)

			signedServiceToken, err := serviceToken.Sign(s.privateKeys, jose.RS256)
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, err.Error())
			}

			signedRefreshToken, err := refreshToken.Sign(s.privateKeys, jose.RS256)
			if err != nil {
				return fiber.NewError(fiber.StatusInternalServerError, err.Error())
			}

			return ctx.JSON(ExchangeResponse{
				AccessToken:  signedServiceToken,
				TokenType:    "Bearer",
				ExpiresIn:    int((time.Minute * 5).Seconds()),
				RefreshToken: signedRefreshToken,
			})
		default:
			return fiber.NewError(fiber.StatusBadRequest, "invalid token kind")
		}
	}

	return fiber.NewError(fiber.StatusBadRequest, "invalid content type")
}

// Refresh godoc
// @Summary      Exchange a Refresh Token
// @Description  Exchange a Refresh Token
// @Tags         auth
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        grantType formData string  true  "Grant Type"
// @Param        refreshToken formData string  true  "Refresh Token"
// @Param        clientID formData string  true  "Client ID"
// @Param        clientSecret formData string  false  "Client Secret"
// @Success      200  {object} RefreshResponse
// @Failure      400  {object} RefreshError
// @Failure      401  {object} RefreshError
// @Failure      500  {object} RefreshError
// @Router       /refresh [post]
func (s *Server) refresh(ctx *fiber.Ctx) error {
	if string(ctx.Request().Header.ContentType()) == fiber.MIMEApplicationForm && ctx.FormValue("grant_type") == "refresh_token" {
		if refreshToken := ctx.FormValue("refresh_token"); refreshToken != "" {
			if clientID := ctx.FormValue("client_id"); clientID != "" {
				client, err := s.storage.GetClient(clientID)
				if err != nil || (!client.Public && (client.Secret != ctx.FormValue("client_secret"))) {
					return ctx.Status(fiber.StatusUnauthorized).JSON(RefreshError{
						Error:            "invalid_client",
						ErrorDescription: "invalid client",
					})
				}
			}
			var r token.RefreshToken
			err := r.Populate(refreshToken, s.publicKeys)
			if err != nil {
				return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
					Error:            "invalid_grant",
					ErrorDescription: "invalid or malformed refresh token",
				})
			}

			if r.Kind != tokenKind.RefreshTokenKind {
				return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
					Error:            "invalid_grant",
					ErrorDescription: "invalid or malformed refresh token",
				})
			}

			if time.Time(r.Expiry).Before(time.Now()) {
				return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
					Error:            "invalid_grant",
					ErrorDescription: "refresh token has expired",
				})
			}

			switch r.For {
			case tokenKind.APITokenKind:
				if apiKey, err := s.storage.GetAPIKey(r.ID); err == nil {

					apiToken := token.NewAPIToken(s.options.Issuer, apiKey, identity.MachineAudiences)
					r.Expiry = token.Time(time.Now().Add(time.Hour * 24 * 7))
					r.IssuedAt = token.Time(time.Now())

					signedAPIToken, err := apiToken.Sign(s.privateKeys, jose.RS256)
					if err != nil {
						return ctx.Status(fiber.StatusInternalServerError).JSON(RefreshError{
							Error:            "server_error",
							ErrorDescription: "internal server error",
						})
					}

					signedRefreshToken, err := r.Sign(s.privateKeys, jose.RS256)
					if err != nil {
						return ctx.Status(fiber.StatusInternalServerError).JSON(RefreshError{
							Error:            "server_error",
							ErrorDescription: "internal server error",
						})
					}

					return ctx.JSON(RefreshResponse{
						AccessToken:  signedAPIToken,
						TokenType:    "Bearer",
						ExpiresIn:    int((time.Minute * 5).Seconds()),
						RefreshToken: signedRefreshToken,
					})
				} else {
					return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
						Error:            "invalid_grant",
						ErrorDescription: "invalid or malformed refresh token",
					})
				}
			case tokenKind.ServiceTokenKind:
				if serviceKey, err := s.storage.GetServiceKey(r.ID, nil, nil); err == nil {
					serviceToken := token.NewServiceToken(s.options.Issuer, serviceKey, identity.MachineAudiences)
					r.Expiry = token.Time(time.Now().Add(time.Hour * 24 * 7))
					r.IssuedAt = token.Time(time.Now())

					signedServiceToken, err := serviceToken.Sign(s.privateKeys, jose.RS256)
					if err != nil {
						return ctx.Status(fiber.StatusInternalServerError).JSON(RefreshError{
							Error:            "server_error",
							ErrorDescription: "internal server error",
						})
					}

					signedRefreshToken, err := r.Sign(s.privateKeys, jose.RS256)
					if err != nil {
						return ctx.Status(fiber.StatusInternalServerError).JSON(RefreshError{
							Error:            "server_error",
							ErrorDescription: "internal server error",
						})
					}

					return ctx.JSON(RefreshResponse{
						AccessToken:  signedServiceToken,
						TokenType:    "Bearer",
						ExpiresIn:    int((time.Minute * 5).Seconds()),
						RefreshToken: signedRefreshToken,
					})
				} else {
					return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
						Error:            "invalid_grant",
						ErrorDescription: "invalid or malformed refresh token",
					})
				}
			}
			return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
				Error:            "invalid_grant",
				ErrorDescription: "invalid or malformed refresh token",
			})
		}
		return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
			Error:            "invalid_request",
			ErrorDescription: "invalid request",
		})
	}
	return ctx.Status(fiber.StatusBadRequest).JSON(RefreshError{
		Error:            "unsupported_grant_type",
		ErrorDescription: "unsupported grant type",
	})
}

func (s *Server) GetPasswordProvider() (dexStorage.Connector, error) {
	return s.storage.GetConnector(server.LocalConnector)
}

func (s *Server) CreatePasswordProvider() error {
	return s.storage.CreateConnector(dexStorage.Connector{
		ID:   server.LocalConnector,
		Type: server.LocalConnector,
		Name: DefaultConnectorName,
	})
}

func (s *Server) DeletePasswordProvider() error {
	connectors, err := s.storage.ListConnectors()
	if err != nil {
		return err
	}

	if len(connectors) == 1 {
		return InvalidConnectorError
	}

	return s.storage.DeleteConnector(server.LocalConnector)
}

func (s *Server) CreateGithubProvider(name string, provider *providers.GithubProvider) error {
	configBytes, err := json.Marshal(provider.Convert())
	if err != nil {
		return err
	}

	connector := dexStorage.Connector{
		ID:     s.githubProviderID(name),
		Type:   githubID,
		Name:   name,
		Config: configBytes,
	}

	return s.storage.CreateConnector(connector)
}

func (s *Server) GetGithubProvider(name string) (*providers.GithubProvider, error) {
	connector, err := s.storage.GetConnector(s.githubProviderID(name))
	if err != nil {
		return nil, err
	}
	config := new(github.Config)
	err = json.Unmarshal(connector.Config, config)
	if err != nil {
		return nil, err
	}
	provider := new(providers.GithubProvider)
	provider.Populate(config)
	provider.ID = connector.Name
	return provider, nil
}

func (s *Server) DeleteGithubProvider(name string) error {
	connectors, err := s.storage.ListConnectors()
	if err != nil {
		return err
	}

	if len(connectors) == 1 {
		return InvalidConnectorError
	}
	return s.storage.DeleteConnector(s.githubProviderID(name))
}

func (s *Server) UpdateGithubProvider(name string, provider *providers.GithubProvider) error {
	_, err := s.GetGithubProvider(name)
	if err != nil {
		return err
	}
	err = s.storage.DeleteConnector(s.githubProviderID(name))
	if err != nil {
		return err
	}
	return s.CreateGithubProvider(name, provider)
}

func (s *Server) ListGithubProvider() ([]*providers.GithubProvider, error) {
	connectors, err := s.storage.ListConnectors()
	if err != nil {
		return nil, err
	}
	var configs []*providers.GithubProvider
	for _, connector := range connectors {
		if connector.Type == githubID {
			config := new(github.Config)
			err = json.Unmarshal(connector.Config, config)
			if err != nil {
				break
			}
			provider := new(providers.GithubProvider)
			provider.Populate(config)
			provider.ID = connector.Name
			configs = append(configs, provider)
		}
	}

	return configs, err
}

func (s *Server) PublicKeySet() *keyset.Public {
	return s.publicKeys
}

func (s *Server) PrivateKeySet() *keyset.Private {
	return s.privateKeys
}

func CreateClient(st storage.Storage, id string, secret string, redirect []string, public bool, name string, logo string) error {
	return st.CreateClient(dexStorage.Client{
		ID:           id,
		Secret:       secret,
		RedirectURIs: redirect,
		TrustedPeers: nil,
		Public:       public,
		Name:         name,
		LogoURL:      logo,
	})
}

func BootstrapConnectors(storage storage.Storage, github *providers.GithubProvider) error {
	connectors, err := storage.ListConnectors()
	if err != nil {
		return err
	}
	if github == nil {
		if len(connectors) == 0 {
			return storage.CreateConnector(dexStorage.Connector{
				ID:     server.LocalConnector,
				Type:   server.LocalConnector,
				Name:   DefaultConnectorName,
				Config: []byte("{}"),
			})
		}
		return nil
	}

	if len(connectors) > 0 {
		_ = storage.DeleteConnector(server.LocalConnector)
	}

	if github != nil {
		configBytes, err := json.Marshal(github.Convert())
		if err != nil {
			return err
		}

		connector := dexStorage.Connector{
			ID:     github.ID,
			Type:   githubID,
			Name:   "Github",
			Config: configBytes,
		}

		err = storage.CreateConnector(connector)
		if err != nil && !errors.Is(err, dexStorage.ErrAlreadyExists) {
			return err
		}
	}

	return nil
}
