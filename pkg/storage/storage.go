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

package storage

import (
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when a key is not found.
	ErrNotFound = errors.New("key not found")

	// ErrAlreadyExists is returned when a key already exists.
	ErrAlreadyExists = errors.New("key already exists")
)

type CommonImmutableData struct {
	// Identifier is the Credential's unique identifier
	Identifier string `json:"identifier"`

	// Creation is the time at which this credential was created
	Creation time.Time `json:"creation"`

	// OrganizationIdentifier is the identifier of the organization that this credential is scoped to
	OrganizationIdentifier string `json:"organization_identifier"`
}

// Storage is the interface that must be implemented by the application
// using this auth library for authentication and session handling.
type Storage interface {
	User
	Registration
	SecretKey
	Session
	APIKey
	ServiceKey
	ServiceSession
	Flow
	Health

	Shutdown() error
}
