/*
	Copyright 2022 Loophole Labs

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
	"time"
)

// SessionEvent is the event that is triggered when a session is created, updated, or deleted
type SessionEvent struct {
	// SessionID is the unique identifier of the session
	SessionID string

	// Deleted indicates whether the session was deleted
	Deleted bool
}

// SecretKeyEvent is the event that is emitted when a secret key is rotated.
type SecretKeyEvent struct {
	// SecretKey is the new secret key
	SecretKey []byte
}

type Storage interface {
	UserExists(ctx context.Context, userID string) (bool, error)
	UserOrganizationExists(ctx context.Context, userID string, organization string) (bool, error)

	SubscribeToSecretKey(ctx context.Context) (<-chan *SecretKeyEvent, error)
	ListSessions(ctx context.Context) ([]string, error)
	SessionExists(ctx context.Context, sessionID string) (bool, error)
	SetSession(ctx context.Context, sessionID string, userID string, organization string, expiry time.Time) error

	SubscribeToSessions(ctx context.Context) (<-chan *SessionEvent, error)
	GetSecretKey(ctx context.Context) ([]byte, error)

	RegistrationEnabled(ctx context.Context) (bool, error)
	NewUser(ctx context.Context, userID string) error
}
