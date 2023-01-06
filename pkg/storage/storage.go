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
	"github.com/loopholelabs/auth/pkg/apikey"
	"github.com/loopholelabs/auth/pkg/claims"
	"github.com/loopholelabs/auth/pkg/session"
)

var (
	ErrNotFound = errors.New("key not found")
)

// SessionEvent is the event that is triggered when a session is created, updated, or deleted
type SessionEvent struct {
	// Session ID is the Session's unique identifier
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

// APIKeyEvent is the event that is emitted when an API key is created, updated, or deleted
type APIKeyEvent struct {
	// APIKeyID is the API Key Identifier
	APIKeyID string

	// Deleted indicates whether the API Key was deleted
	Deleted bool

	// APIKey is the API Key that was created or updated.
	// This will be nil if the API Key was deleted.
	APIKey *apikey.APIKey
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

	SubscribeToSessionIDs(ctx context.Context) (<-chan *SessionEvent, error)
	ListSessionIDs(ctx context.Context) ([]string, error)
	SessionIDExists(ctx context.Context, sessionID string) (bool, error)

	SetSession(ctx context.Context, session *session.Session) error
	GetSession(ctx context.Context, sessionID string) (*session.Session, error)
	DeleteSession(ctx context.Context, sessionID string) error

	SubscribeToAPIKeys(ctx context.Context) (<-chan *APIKeyEvent, error)
	ListAPIKeys(ctx context.Context) ([]*apikey.APIKey, error)
	GetAPIKey(ctx context.Context, id string) (*apikey.APIKey, error)
}
