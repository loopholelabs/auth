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

type ConfigResponse struct {
	GithubEnabled bool `json:"github_enabled"`
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
	ServiceSessionID     string `json:"service_session_id"`
	ServiceSessionSecret string `json:"service_session_secret"`
	ServiceKeyID         string `json:"service_key_id"`
	UserID               string `json:"user_id"`
	Organization         string `json:"organization"`
	ResourceType         string `json:"resource_type"`
	ResourceID           string `json:"resource_id"`
}
