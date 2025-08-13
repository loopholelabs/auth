//SPDX-License-Identifier: Apache-2.0

//nolint:revive
package device

import (
	"net/http"
)

type DeviceValidateRequest struct {
	Code string `query:"code" required:"true" minLength:"8" maxLength:"8" doc:"device flow code"`
}

type DevicePollRequest struct {
	Poll string `query:"poll" required:"true" minLength:"36" maxLength:"36" doc:"poll code"`
}

type DeviceLoginResponseBody struct {
	Code               string `json:"code" doc:"device flow code"`
	Poll               string `json:"poll" doc:"poll code for polling status"`
	PollingRateSeconds uint64 `json:"polling_rate_seconds" doc:"polling rate in seconds"`
}

type DeviceLoginResponse struct {
	Body DeviceLoginResponseBody
}

type DevicePollResponse struct {
	SessionCookie *http.Cookie `header:"Set-Cookie" required:"true" doc:"session cookie"`
}
