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

package auth

const (
	APIKeyPrefixString            = "AK-"
	ServiceKeyPrefixString        = "SK-"
	ServiceKeySessionPrefixString = "SS-"
)

var (
	APIKeyPrefix            = []byte(APIKeyPrefixString)
	ServiceKeySessionPrefix = []byte(ServiceKeySessionPrefixString)
)

const (
	SessionContextKey           = "session"
	APIKeyContextKey            = "apikey"
	ServiceKeySessionContextKey = "service"
	UserContextKey              = "user"
	OrganizationContextKey      = "organization"
)

type Kind string

const (
	KindContextKey Kind = "kind"

	KindSession    Kind = "session"
	KindAPIKey     Kind = "api"
	KindServiceKey Kind = "service"
)
