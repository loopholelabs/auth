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

package apikey

// APIKey is a user's API Key
type APIKey struct {
	// Identifier is the API Key's unique identifier
	Identifier string `json:"identifier"`

	// Salt is the API Key's salt
	Salt []byte `json:"salt"`

	// Hash is the hashed secret of the API Key
	Hash []byte `json:"hash"`

	// Creator is the creator's unique identifier
	Creator string `json:"creator"`

	// Organization is the organization that the API Key is scoped to
	Organization string `json:"organization"`
}
