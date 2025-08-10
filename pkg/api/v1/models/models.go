//SPDX-License-Identifier: Apache-2.0

package models

const (
	SessionCookie = "authentication-session"
)

type DeviceFlowResponse struct {
	Code               string `json:"code"`
	Poll               string `json:"poll"`
	PollingRateSeconds uint64 `json:"polling_rate_seconds"`
}

type DeviceCallbackResponse struct {
	Identifier string `json:"identifier"`
}

type PublicResponse struct {
	Key string `json:"key"`
}
