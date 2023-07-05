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
	"context"
	"github.com/loopholelabs/auth/pkg/claims"
)

// User is the interface that must be implemented to store user data.
type User interface {
	// UserExists verifies whether the given identifier exists. If there is an error
	// while checking if the user exists, an error is returned, otherwise
	// the boolean indicates whether the user exists. An error should not be
	// returned if the user does not exist.
	UserExists(ctx context.Context, identifier string) (bool, error)

	// UserOrganizationExists verifies whether the given user identifier is part of the
	// given organization. If there is an error while checking if the user is
	// part of the organization, an error is returned, otherwise the boolean indicates
	// whether the user is part of the organization. An error should not be
	// returned if the user is not part of the organization, if the organization
	// does not exist, or if the user does not exist - instead, the boolean
	// should be false.
	UserOrganizationExists(ctx context.Context, identifier string, organization string) (bool, error)

	// NewUser creates a new user with the given claims. If the user already
	// exists, an error is returned. If the user does not exist, the user is
	// created and the claims are set. If there is an error while creating the
	// user, an error is returned.
	NewUser(ctx context.Context, claims *claims.Claims) error
}
