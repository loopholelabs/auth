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

package flow

import "errors"

var (
	ErrInvalidOptions = errors.New("invalid options")
)

// Key uniquely identifies authentication providers
//
// Each provider must create its own globally unique key
type Key string

// Flow is an authentication flow provider that authorizes
// a user and returns a set of claims
type Flow interface {
	// Key returns the authentication provider's unique key
	Key() Key

	// Start starts the Provider
	Start() error

	// Stop stops the Provider
	Stop() error
}