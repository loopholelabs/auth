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

package servicesession

import (
	"github.com/google/uuid"
	"github.com/loopholelabs/auth"
	"github.com/loopholelabs/auth/pkg/servicekey"
	"golang.org/x/crypto/bcrypt"
)

// ServiceSession represents a user's authenticated service key session
type ServiceSession struct {
	// ID is the service session's unique identifier
	ID string `json:"id"`

	// Hash is the hashed secret of the service session
	Hash []byte `json:"hash"`

	// ServiceKeyID is the ID of the Service Key that the service session is associated with
	ServiceKeyID string `json:"service_key_id"`

	// UserID is the user's unique identifier
	UserID string `json:"user_id"`

	// Organization is the organization that the Service Key belongs to (optional)
	Organization string `json:"organization"`

	// ResourceType is the resource type that the Service Key is authorized to access (optional)
	ResourceType string `json:"resource_type"`

	// ResourceID is the resource that the Service Key is authorized to access (optional unless ResourceType is set)
	ResourceID string `json:"resource_id"`
}

// New returns a new service session for a user with the given service key
func New(servicekey *servicekey.ServiceKey) (*ServiceSession, []byte, error) {
	id := uuid.New().String()
	secret := []byte(auth.ServiceSessionPrefixString + uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(secret, bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}
	return &ServiceSession{
		ID:           id,
		Hash:         hash,
		ServiceKeyID: servicekey.ID,
		UserID:       servicekey.UserID,
		Organization: servicekey.Organization,
		ResourceType: servicekey.ResourceType,
		ResourceID:   servicekey.ResourceID,
	}, secret, nil
}
