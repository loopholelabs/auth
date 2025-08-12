//SPDX-License-Identifier: Apache-2.0

package device

import (
	"github.com/loopholelabs/auth/pkg/api/models"
)

type DeviceValidateRequest struct {
	Code string `query:"code" required:"true" minLength:"8" maxLength:"8" doc:"device flow code"`
}

type DevicePollRequest struct {
	Poll string `query:"poll" required:"true" minLength:"36" maxLength:"36" doc:"poll code"`
}

type DeviceLoginBody struct {
	Code               string `json:"code" doc:"device flow code"`
	Poll               string `json:"poll" doc:"poll code for polling status"`
	PollingRateSeconds uint64 `json:"polling_rate_seconds" doc:"polling rate in seconds"`
}

type DeviceLoginResponse struct {
	Body DeviceLoginBody
}

type DevicePollResponse struct {
	Headers models.SessionHeaders
}
