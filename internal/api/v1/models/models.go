/*
	Copyright 2023 Loophole Labs

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

package models

import (
	"github.com/loopholelabs/auth"
	"github.com/loopholelabs/auth/pkg/servicekey"
)

type ConfigResponse struct {
	GithubEnabled  bool   `json:"github_enabled"`
	GoogleEnabled  bool   `json:"google_enabled"`
	MagicEnabled   bool   `json:"magic_enabled"`
	DeviceEnabled  bool   `json:"device_enabled"`
	Endpoint       string `json:"endpoint"`
	DefaultNextURL string `json:"default_next_url"`
}

type DeviceFlowResponse struct {
	DeviceCode  string `json:"device_code"`
	UserCode    string `json:"user_code"`
	PollingRate int64  `json:"polling_rate"`
}

type DeviceCallbackResponse struct {
	Identifier string `json:"identifier"`
}

type ServiceKeyLoginResponse struct {
	ServiceSessionID     string                `json:"service_session_id"`
	ServiceSessionSecret string                `json:"service_session_secret"`
	ServiceKeyID         string                `json:"service_key_id"`
	Owner                string                `json:"owner"`
	Organization         string                `json:"organization"`
	Resources            []servicekey.Resource `json:"resources"`
}

type UserInfoResponse struct {
	Identifier   string    `json:"identifier"`
	Email        string    `json:"email"`
	Kind         auth.Kind `json:"kind"`
	Organization string    `json:"organization"`
}

type HealthResponse struct {
	Subscriptions bool `json:"subscriptions"`
}
