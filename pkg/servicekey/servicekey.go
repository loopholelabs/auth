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

package servicekey

import "time"

// Resource represents a resource that a Service Key is authorized to access
type Resource struct {
	// ID is the resource's unique identifier
	ID string `json:"id"`

	// Type is the resource's type
	Type string `json:"type"`
}

// ServiceKey represents a Service Key
type ServiceKey struct {
	// ID is the Service Key's unique identifier
	ID string `json:"id"`

	// Salt is the Service Key's salt
	Salt []byte `json:"salt"`

	// Hash is the hashed secret of the Service Key session
	Hash []byte `json:"hash"`

	// UserID is the user's unique identifier
	UserID string `json:"user_id"`

	// Organization is the organization that the Service Key belongs to (optional)
	Organization string `json:"organization"`

	// Resources are the resources that the Service Key is authorized to access (optional)
	Resources []Resource `json:"resources"`

	// MaxUses is the maximum number of times the Service Key can be used (optional)
	MaxUses int64 `json:"max_uses"`

	// NumUsed is the number of times the Service Key has been used (optional unless MaxUses is set)
	NumUsed int64 `json:"num_used"`

	// Expires is the time at which the Service Key expires (optional)
	Expires time.Time `json:"expires"`
}
