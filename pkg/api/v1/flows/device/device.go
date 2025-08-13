//SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/middleware/fiber"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/credential/cookies"
	"github.com/loopholelabs/auth/pkg/manager/flow/device"
)

const (
	PollingRate = time.Second * 5
)

type Device struct {
	logger  types.Logger
	options options.Options
}

func New(options options.Options, logger types.Logger) *Device {
	return &Device{
		logger:  logger.SubLogger("DEVICE"),
		options: options,
	}
}

func (d *Device) Register(prefixes []string, group huma.API) {
	prefixes = append(prefixes, "device")
	group = huma.NewGroup(group, "/device")

	loginPrefix := append(prefixes, "login") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(loginPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/login",
		Summary:       "initiate device code flow",
		Description:   "initiates the device code flow and returns codes for polling and validation",
		Tags:          loginPrefix,
		DefaultStatus: 200,
		Errors:        []int{401, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("login", d.logger)},
	}, d.login)

	validatePrefix := append(prefixes, "validate") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(validatePrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/validate",
		Summary:       "validate device code",
		Description:   "validates that a device code exists and is valid",
		Tags:          validatePrefix,
		DefaultStatus: 200,
		Errors:        []int{401, 404, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("validate", d.logger)},
	}, d.validate)

	pollPrefix := append(prefixes, "poll") //nolint:gocritic
	huma.Register(group, huma.Operation{
		OperationID:   strings.Join(pollPrefix, "-"),
		Method:        http.MethodGet,
		Path:          "/poll",
		Summary:       "poll for device code flow completion",
		Description:   "polls the device flow to check if authentication is complete",
		Tags:          pollPrefix,
		DefaultStatus: 200,
		Errors:        []int{401, 403, 404, 429, 500},
		Middlewares:   huma.Middlewares{fiber.LogIP("poll", d.logger)},
	}, d.poll)
}

func (d *Device) login(ctx context.Context, _ *struct{}) (*DeviceLoginResponse, error) {
	if d.options.Manager.Device() == nil {
		return nil, huma.Error401Unauthorized("device provider is not enabled")
	}

	code, poll, err := d.options.Manager.Device().CreateFlow(ctx)
	if err != nil {
		d.logger.Error().Err(err).Msg("error creating flow")
		return nil, huma.Error500InternalServerError("error creating flow")
	}

	return &DeviceLoginResponse{
		Body: DeviceLoginResponseBody{
			Code:               code,
			Poll:               poll,
			PollingRateSeconds: uint64(PollingRate.Truncate(time.Second).Seconds()),
		},
	}, nil
}

func (d *Device) validate(ctx context.Context, input *DeviceValidateRequest) (*struct{}, error) {
	if d.options.Manager.Device() == nil {
		return nil, huma.Error401Unauthorized("device provider is not enabled")
	}

	identifier, err := d.options.Manager.Device().ExistsFlow(ctx, input.Code)
	if err != nil {
		d.logger.Error().Err(err).Msg("error checking if flow exists")
		return nil, huma.Error500InternalServerError("error checking if flow exists")
	}
	if identifier == "" {
		return nil, huma.Error404NotFound("flow does not exist")
	}

	return nil, nil //nolint:nilnil
}

func (d *Device) poll(ctx context.Context, input *DevicePollRequest) (*DevicePollResponse, error) {
	if d.options.Manager.Device() == nil {
		return nil, huma.Error401Unauthorized("device provider is not enabled")
	}

	sessionIdentifier, err := d.options.Manager.Device().PollFlow(ctx, input.Poll, PollingRate)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, huma.Error404NotFound("flow does not exist")
		case errors.Is(err, device.ErrRateLimitFlow):
			return nil, huma.Error429TooManyRequests("polling rate limit exceeded")
		case errors.Is(err, device.ErrFlowNotCompleted):
			return nil, huma.Error403Forbidden("incomplete flow")
		default:
			d.logger.Error().Err(err).Msg("error polling flow")
			return nil, huma.Error500InternalServerError("error polling flow")
		}
	}

	session, err := d.options.Manager.CreateExistingSession(ctx, sessionIdentifier)
	if err != nil {
		d.logger.Error().Err(err).Msg("error creating session")
		return nil, huma.Error500InternalServerError("error creating session")
	}

	cookie, err := cookies.Create(session, d.options)
	if err != nil {
		d.logger.Error().Err(err).Msg("error creating cookie")
		return nil, huma.Error500InternalServerError("error creating cookie")
	}

	return &DevicePollResponse{
		SessionCookie: cookie,
	}, nil
}
