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

import (
	"errors"
	"time"
)

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

// Device holds the Device Code Authorization Flow
type Device struct {
	Identifier        string    `json:"identifier"`
	DeviceCode        string    `json:"device_code"`
	UserCode          string    `json:"user_code"`
	SessionIdentifier string    `json:"session_identifier"`
	EncryptedSession  string    `json:"encrypted_session"`
	LastPoll          time.Time `json:"last_poll"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// Github holds the Github Authorization Flow
type Github struct {
	Identifier       string `json:"identifier"`
	Verifier         string `json:"verifier"`
	Challenge        string `json:"challenge"`
	NextURL          string `json:"next_url"`
	Organization     string `json:"organization"`
	DeviceIdentifier string `json:"device_identifier"`
}

// Google holds the Google Authorization Flow
type Google struct {
	Identifier       string `json:"identifier"`
	Verifier         string `json:"verifier"`
	Challenge        string `json:"challenge"`
	NextURL          string `json:"next_url"`
	Organization     string `json:"organization"`
	DeviceIdentifier string `json:"device_identifier"`
}

// Magic holds the Magic Authorization Flow
type Magic struct {
	Email            string `json:"email"`
	IPAddress        string `json:"ip_address"`
	Salt             []byte `json:"salt"`
	Hash             []byte `json:"hash"`
	NextURL          string `json:"next_url"`
	Organization     string `json:"organization"`
	DeviceIdentifier string `json:"device_identifier"`
}
