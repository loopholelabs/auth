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
	"errors"
	"github.com/loopholelabs/auth/pkg/claims"
	"github.com/loopholelabs/auth/pkg/kind"
	"time"
)

var (
	ErrNotFound = errors.New("key not found")
)

// SessionEvent is the event that is triggered when a session is created, updated, or deleted
type SessionEvent struct {
	// SessionID is the unique identifier of the session
	SessionID string

	// Deleted indicates whether the session was deleted
	Deleted bool
}

// SecretKeyEvent is the event that is emitted when a secret key is rotated
type SecretKeyEvent struct {
	// SecretKey is the new secret key
	SecretKey []byte
}

// RegistrationEvent is the event that is emitted when registration is enabled or disabled
type RegistrationEvent struct {
	// Enabled indicates whether registration is enabled
	Enabled bool
}

type Storage interface {
	UserExists(ctx context.Context, userID string) (bool, error)
	UserOrganizationExists(ctx context.Context, userID string, organization string) (bool, error)
	NewUser(ctx context.Context, claims *claims.Claims) error

	SubscribeToRegistration(ctx context.Context) (<-chan *RegistrationEvent, error)
	GetRegistration(ctx context.Context) (bool, error)
	SetRegistration(ctx context.Context, enabled bool) error

	SubscribeToSecretKey(ctx context.Context) (<-chan *SecretKeyEvent, error)
	GetSecretKey(ctx context.Context) ([]byte, error)
	SetSecretKey(ctx context.Context, secretKey []byte) error

	SubscribeToSessions(ctx context.Context) (<-chan *SessionEvent, error)
	ListSessions(ctx context.Context) ([]string, error)
	SessionExists(ctx context.Context, sessionID string) (bool, error)
	SetSession(ctx context.Context, sessionKind kind.Kind, sessionID string, userID string, organization string, expiry time.Time) error

	GetAPIKey(ctx context.Context)
}
