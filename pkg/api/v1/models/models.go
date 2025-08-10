//SPDX-License-Identifier: Apache-2.0

package models

import "github.com/loopholelabs/auth/pkg/validator"

const (
	SessionCookie = "authentication-session"
)

type DeviceFlowResponse struct {
	Code               string `json:"code"`
	Poll               string `json:"poll"`
	PollingRateSeconds uint64 `json:"polling_rate_seconds"`
}

type PublicResponse struct {
	PublicKey           string                         `json:"public_key"`
	PreviousPublicKey   string                         `json:"previous_public_key"`
	RevokedSessions     []string                       `json:"revoked_sessions"`
	InvalidatedSessions []validator.InvalidatedSession `json:"invalidated_sessions"`
}
