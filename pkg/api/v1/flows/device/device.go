//SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/models"
	"github.com/loopholelabs/auth/pkg/manager/flow/device"
)

const (
	PollingRate = time.Second * 5
)

type Device struct {
	logger  types.Logger
	options options.Options
}

// Request and Response types

type DeviceLoginBody struct {
	Code               string `json:"code" doc:"Device flow code"`
	Poll               string `json:"poll" doc:"Poll code for checking status"`
	PollingRateSeconds uint64 `json:"polling_rate_seconds" doc:"Polling rate in seconds"`
}

type LoginOutput struct {
	Body DeviceLoginBody
}

type ValidateInput struct {
	Code string `query:"code" required:"true" minLength:"8" maxLength:"8" doc:"Device flow code"`
}

type ValidateOutput struct {
	StatusCode int `json:"-" default:"200"`
}

type PollInput struct {
	Code string `query:"code" required:"true" minLength:"36" maxLength:"36" doc:"Poll code"`
}

type DevicePollHeaders struct {
	SetCookie *http.Cookie `header:"Set-Cookie" doc:"Session cookie"`
}

type PollOutput struct {
	StatusCode int `json:"-" default:"200"`
	Headers    DevicePollHeaders
}

// RegisterEndpoints registers the Device flow endpoints with Huma
func RegisterEndpoints(api huma.API, options options.Options, logger types.Logger) {
	d := &Device{
		logger:  logger.SubLogger("DEVICE"),
		options: options,
	}

	huma.Register(api, huma.Operation{
		OperationID: "device-login",
		Method:      "GET",
		Path:        "/flows/device/login",
		Summary:     "Initiate device flow",
		Description: "Initiates the device code flow and returns codes for authentication",
		Tags:        []string{"device", "login"},
	}, d.login)

	huma.Register(api, huma.Operation{
		OperationID: "device-validate",
		Method:      "GET",
		Path:        "/flows/device/validate",
		Summary:     "Validate device code",
		Description: "Validates that a device code exists and is valid",
		Tags:        []string{"device", "validate"},
	}, d.validate)

	huma.Register(api, huma.Operation{
		OperationID: "device-poll",
		Method:      "GET",
		Path:        "/flows/device/poll",
		Summary:     "Poll for completion",
		Description: "Polls the device flow to check if authentication is complete",
		Tags:        []string{"device", "poll"},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Authentication complete",
				Headers: map[string]*huma.Param{
					"Set-Cookie": {
						Description: "Session cookie",
						Required:    true,
					},
				},
			},
		},
	}, d.poll)
}

// Handler implementations

func (d *Device) login(ctx context.Context, _ *struct{}) (*LoginOutput, error) {
	// Extract Fiber context for IP logging
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)
	d.logger.Debug().Str("IP", fiberCtx.IP()).Msg("login")

	if d.options.Manager.Device() == nil {
		return nil, huma.Error401Unauthorized("device provider is not enabled")
	}

	code, poll, err := d.options.Manager.Device().CreateFlow(ctx)
	if err != nil {
		d.logger.Error().Err(err).Msg("error creating flow")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	output := &LoginOutput{}
	output.Body.Code = code
	output.Body.Poll = poll
	output.Body.PollingRateSeconds = uint64(PollingRate.Truncate(time.Second).Seconds())

	return output, nil
}

func (d *Device) validate(ctx context.Context, input *ValidateInput) (*ValidateOutput, error) {
	// Extract Fiber context for IP logging
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)
	d.logger.Debug().Str("IP", fiberCtx.IP()).Msg("validate")

	if d.options.Manager.Device() == nil {
		return nil, huma.Error401Unauthorized("device provider is not enabled")
	}

	identifier, err := d.options.Manager.Device().ExistsFlow(ctx, input.Code)
	if err != nil {
		d.logger.Error().Err(err).Msg("error checking if flow exists")
		return nil, huma.Error500InternalServerError("internal server error")
	}
	if identifier == "" {
		return nil, huma.Error404NotFound("flow does not exist")
	}

	return &ValidateOutput{StatusCode: 200}, nil
}

func (d *Device) poll(ctx context.Context, input *PollInput) (*PollOutput, error) {
	// Extract Fiber context for IP logging
	humaCtx := ctx.(huma.Context)
	fiberCtx := humafiber.Unwrap(humaCtx)
	d.logger.Debug().Str("IP", fiberCtx.IP()).Msg("poll")

	if d.options.Manager.Device() == nil {
		return nil, huma.Error401Unauthorized("device provider is not enabled")
	}

	sessionIdentifier, err := d.options.Manager.Device().PollFlow(ctx, input.Code, PollingRate)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, huma.Error404NotFound("flow does not exist")
		case errors.Is(err, device.ErrRateLimitFlow):
			return nil, huma.Error429TooManyRequests("polling rate exceeded")
		case errors.Is(err, device.ErrFlowNotCompleted):
			return nil, huma.Error403Forbidden("incomplete flow")
		default:
			d.logger.Error().Err(err).Msg("error polling flow")
			return nil, huma.Error500InternalServerError("internal server error")
		}
	}

	session, err := d.options.Manager.CreateExistingSession(ctx, sessionIdentifier)
	if err != nil {
		d.logger.Error().Err(err).Msg("error creating session")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	token, err := d.options.Manager.SignSession(session)
	if err != nil {
		d.logger.Error().Err(err).Msg("error signing session")
		return nil, huma.Error500InternalServerError("internal server error")
	}

	return &PollOutput{
		StatusCode: 200,
		Headers: DevicePollHeaders{
			SetCookie: &http.Cookie{
				Name:     models.SessionCookie,
				Value:    token,
				Expires:  session.ExpiresAt,
				Domain:   d.options.Endpoint,
				Secure:   d.options.TLS,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			},
		},
	}, nil
}
