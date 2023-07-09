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
	// Identifier is the service session's unique identifier
	//
	// This is different from the Service Key's Identifier
	Identifier string `json:"id"`

	// Salt is the service session's salt
	//
	// This is randomly generated and used to hash the secret of the service session, and is
	// different from the Service Key's Salt
	Salt []byte `json:"salt"`

	// Hash is the hashed secret of the service session
	//
	// This is generated from the service session's identifier, secret, and salt.
	// The secret is never stored. This is different from the Service Key's Hash.
	Hash []byte `json:"hash"`

	// ServiceKeyIdentifier is the identifier of the Service Key that the service session is associated with
	ServiceKeyIdentifier string `json:"service_key_identifier"`

	// Creator is the creator's unique identifier
	Creator string `json:"creator"`

	// Organization is the organization that the Service Key is scoped to
	Organization string `json:"organization"`

	// Resources are the resources that the Service Key is authorized to access (optional)
	Resources []servicekey.Resource `json:"resources"`
}

// New returns a new service session for a user with the given service key
func New(serviceKey *servicekey.ServiceKey) (*ServiceSession, []byte, error) {
	identifier := auth.ServiceSessionPrefixString + uuid.New().String()
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}
	return &ServiceSession{
		Identifier:           identifier,
		Salt:                 salt,
		Hash:                 hash,
		ServiceKeyIdentifier: serviceKey.Identifier,
		Creator:              serviceKey.Creator,
		Organization:         serviceKey.Organization,
		Resources:            serviceKey.Resources,
	}, secret, nil
}
