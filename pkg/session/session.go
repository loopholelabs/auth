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

package session

import (
	"github.com/google/uuid"
	"github.com/loopholelabs/auth/pkg/flow"
	"github.com/loopholelabs/auth/pkg/sessionKind"
	"time"
)

const (
	// Expiry is the session expiry time for garbage collection purposes
	Expiry = time.Hour * 24 * 7 // 7 days

	// Skew is the amount of time before a session expires that we will consider it close to expiring
	Skew = time.Hour * 24 // 1 day
)

// Session represents a user's authenticated session
type Session struct {
	Creation     time.Time               `json:"creation"`
	Expiry       time.Time               `json:"expiry"`
	Kind         sessionKind.SessionKind `json:"kind"`
	Identifier   string                  `json:"identifier"`
	Provider     flow.Key                `json:"provider"`
	Creator      string                  `json:"creator"`
	Organization string                  `json:"organization"`
}

// New returns a new session for a user with the given kind key, provider key, creator identifier, and organization
func New(kind sessionKind.SessionKind, provider flow.Key, creator string, organization string) *Session {
	return &Session{
		Creation:     time.Now(),
		Expiry:       time.Now().Add(Expiry),
		Kind:         kind,
		Identifier:   uuid.New().String(),
		Provider:     provider,
		Creator:      creator,
		Organization: organization,
	}
}

// Expired returns true if the session has expired
func (s *Session) Expired() bool {
	return time.Now().After(s.Expiry)
}

// CloseToExpiry returns true if the session is close to expiring
func (s *Session) CloseToExpiry() bool {
	return time.Now().After(s.Expiry.Add(-Skew))
}

func (s *Session) Refresh() {
	s.Expiry = time.Now().Add(Expiry)
}
