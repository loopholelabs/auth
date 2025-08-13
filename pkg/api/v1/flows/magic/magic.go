//SPDX-License-Identifier: Apache-2.0

package magic

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"

	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/danielgtaylor/huma/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/mailer"
	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential/cookies"
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
)

type Magic struct {
	logger        types.Logger
	emailVerifier *emailverifier.Verifier
	options       options.Options
}

func New(options options.Options, logger types.Logger) *Magic {
	return &Magic{
		logger:        logger.SubLogger("MAGIC"),
		emailVerifier: emailverifier.NewVerifier(),
		options:       options,
	}
}

func (m *Magic) Register(prefixes []string, group huma.API) {
	prefixes = append(prefixes, "magic")
	group = huma.NewGroup(group, "/magic")

	loginPrefix := append(prefixes, "login") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(loginPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/login",
		Summary:       "send magic link",
		Description:   "sends a magic link to the specified email address",
		Tags:          loginPrefix,
		DefaultStatus: 200,
		Errors:        []int{400, 401, 404, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("login", m.logger)},
	}, m.login)

	callbackPrefix := append(prefixes, "callback") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(callbackPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/callback",
		Summary:       "magic link callback",
		Description:   "Handles the magic link callback and creates a session",
		Tags:          callbackPrefix,
		DefaultStatus: 307,
		Errors:        []int{401, 404, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("callback", m.logger)},
	}, m.callback)
}

func (m *Magic) login(ctx context.Context, input *MagicLoginRequest) (*struct{}, error) {
	if m.options.Manager.Magic() == nil {
		return nil, huma.Error401Unauthorized("magic provider is not enabled")
	}

	if m.options.Manager.Mailer() == nil {
		return nil, huma.Error401Unauthorized("email provider is not enabled")
	}

	ret, err := m.emailVerifier.Verify(input.Email)
	if err != nil || !ret.Syntax.Valid || !ret.HasMxRecords {
		return nil, huma.Error400BadRequest("invalid email address")
	}

	var deviceIdentifier string
	if input.Code != "" && len(input.Code) == 8 {
		if m.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
		deviceIdentifier, err = m.options.Manager.Device().ExistsFlow(ctx, input.Code)
		if err != nil {
			m.logger.Error().Err(err).Msg("error checking if flow exists")
			return nil, huma.Error500InternalServerError("error checking if flow exists")
		}
		if deviceIdentifier == "" {
			return nil, huma.Error404NotFound("device flow does not exist")
		}
	}

	token, err := m.options.Manager.Magic().CreateFlow(ctx, input.Email, deviceIdentifier, "", input.Next)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to get token")
		return nil, huma.Error500InternalServerError("failed to get token")
	}

	var callback url.URL
	callback.Scheme = "http"
	if m.options.TLS {
		callback.Scheme = "https"
	}
	callback.Host = m.options.Endpoint
	callback.Path = "/v1/flows/magic/callback"
	q := callback.Query()
	q.Add("token", token)
	callback.RawQuery = q.Encode()

	err = m.options.Manager.Mailer().SendMagicLink(ctx, mailer.Email{
		To: input.Email,
	}, callback.String(), magic.Expiry)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to send magic link")
		return nil, huma.Error500InternalServerError("failed to send magic link")
	}

	return nil, nil //nolint:nilnil
}

func (m *Magic) callback(ctx context.Context, input *MagicCallbackRequest) (*MagicCallbackResponse, error) {
	if m.options.Manager.Magic() == nil {
		return nil, huma.Error401Unauthorized("magic provider is not enabled")
	}

	f, err := m.options.Manager.Magic().CompleteFlow(ctx, input.Token)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, huma.Error404NotFound("flow does not exist")
		case errors.Is(err, magic.ErrInvalidToken):
			return nil, huma.Error401Unauthorized("invalid token")
		default:
			m.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("failed to complete flow")
		}
	}

	if f.DeviceIdentifier != "" {
		if m.options.Manager.Device() == nil {
			return nil, huma.Error401Unauthorized("device provider is not enabled")
		}
	}

	session, err := m.options.Manager.CreateSession(ctx, f, flow.MagicProvider)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to create session")
		return nil, huma.Error500InternalServerError("failed to create session")
	}

	response := &MagicCallbackResponse{
		Location: f.NextURL,
	}

	if f.DeviceIdentifier != "" {
		// Device flow - complete the device flow but don't set cookie
		err = m.options.Manager.Device().CompleteFlow(ctx, f.DeviceIdentifier, session.Identifier)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to complete flow")
			return nil, huma.Error500InternalServerError("failed to complete flow")
		}
	} else {
		response.SessionCookie, err = cookies.Create(session, m.options)
		if err != nil {
			m.logger.Error().Err(err).Msg("error creating cookie")
			return nil, huma.Error500InternalServerError("error creating cookie")
		}
	}

	return response, nil
}
