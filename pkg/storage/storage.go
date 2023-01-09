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
	"github.com/loopholelabs/auth/pkg/servicekey"
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

// ServiceKeySessionEvent is the event that is triggered when a service key session is created, updated, or deleted
type ServiceKeySessionEvent struct {
	// ServiceKeySessionID is the Service Key Session's unique identifier
	ServiceKeySessionID string

	// Deleted indicates whether the session was deleted
	Deleted bool

	// ServiceKeySession is the Service Key Session that was created or updated.
	// This will be nil if the Service Key Session was deleted.
	ServiceKeySession *servicekey.Session
}

// Storage is the interface that must be implemented by the application
// using this auth library for authentication and session handling.
type Storage interface {
	// UserExists verifies whether the given userID exists. If there is an error
	// while checking if the user exists, an error is returned, otherwise
	// the boolean indicates whether the user exists. An error should not be
	// returned if the user does not exist.
	UserExists(ctx context.Context, userID string) (bool, error)
	// UserOrganizationExists verifies whether the given userID is part of the
	// given organization. If there is an error while checking if the user
	// exists, an error is returned, otherwise the boolean indicates whether
	// the user exists. An error should not be returned if the user does not
	// exist or if the user is not part of the organization.
	UserOrganizationExists(ctx context.Context, userID string, organization string) (bool, error)
	// NewUser creates a new user with the given claims. If the user already
	// exists, an error is returned. If the user does not exist, the user is
	// created and the claims are set. If there is an error while creating the
	// user, an error is returned.
	NewUser(ctx context.Context, claims *claims.Claims) error

	// SubscribeToRegistration subscribes to registration events. When registration
	// is enabled or disabled, the event is emitted on the given channel. Cancelling
	// the provided context will unsubscribe from registration events.
	SubscribeToRegistration(ctx context.Context) (<-chan *RegistrationEvent, error)
	// GetRegistration returns whether registration is enabled. If there is an error
	// while getting the registration status, an error is returned. If there is no
	// error, the boolean indicates whether registration is enabled.
	GetRegistration(ctx context.Context) (bool, error)
	// SetRegistration sets whether registration is enabled. If there is an error
	// while setting the registration status, an error is returned.
	// If there is no error, the boolean indicates whether registration is enabled.
	SetRegistration(ctx context.Context, enabled bool) error

	// SubscribeToSecretKey subscribes to secret key events. When the secret key is
	// rotated, the event is emitted on the given channel. Cancelling the provided
	// context will unsubscribe from secret key events.
	SubscribeToSecretKey(ctx context.Context) (<-chan *SecretKeyEvent, error)
	// GetSecretKey returns the current secret key. If there is an error while
	// getting the secret key, an error is returned.
	// If there is no error, the secret key is returned.
	// The secret key should be exactly 32 bytes long.
	GetSecretKey(ctx context.Context) ([]byte, error)
	// SetSecretKey sets the current secret key. If there is an error while
	// setting the secret key, an error is returned.
	// If there is no error, the secret key is returned.
	// The secret key should be exactly 32 bytes long.
	SetSecretKey(ctx context.Context, secretKey []byte) error

	// SubscribeToSessionIDs subscribes to session events. When a session is created,
	// updated, or deleted, the event is emitted on the given channel. Cancelling
	// the provided context will unsubscribe from session events.
	SubscribeToSessionIDs(ctx context.Context) (<-chan *SessionEvent, error)
	// ListSessionIDs returns a list of all session IDs. If there is an error while
	// listing the session IDs, an error is returned.
	// If there is no error, the list of session IDs is returned.
	ListSessionIDs(ctx context.Context) ([]string, error)
	//SessionIDExists verifies whether the given sessionID exists. If there is an error
	// while checking if the sessionID exists, an error is returned, otherwise
	// the boolean indicates whether the sessionID exists. An error should not be
	// returned if the sessionID does not exist.
	SessionIDExists(ctx context.Context, sessionID string) (bool, error)

	// SetSession sets the session for the given session.ID. If there is an error
	// while setting the session, an error is returned.
	SetSession(ctx context.Context, session *session.Session) error
	// GetSession returns the session for the given sessionID. If
	// there is an error while getting the session, an error is returned.
	// If there is no error, the session is returned.
	GetSession(ctx context.Context, sessionID string) (*session.Session, error)
	// DeleteSession deletes the session for the given sessionID. If
	// there is an error while deleting the session, an error is returned.
	// An error is returned if the session does not exist.
	DeleteSession(ctx context.Context, sessionID string) error

	// SubscribeToAPIKeys subscribes to API key events. When an API key is created,
	// updated, or deleted, the event is emitted on the given channel. Cancelling
	// the provided context will unsubscribe from API key events.
	SubscribeToAPIKeys(ctx context.Context) (<-chan *APIKeyEvent, error)
	// ListAPIKeys returns a list of all API keys. If there is an error while
	// listing the API keys, an error is returned. If there is no error, the list
	// of API keys is returned.
	ListAPIKeys(ctx context.Context) ([]*apikey.APIKey, error)
	// GetAPIKey returns the API key for the given API key ID. If
	// there is an error while getting the API key, an error is returned.
	// If there is no error, the API key is returned.
	GetAPIKey(ctx context.Context, id string) (*apikey.APIKey, error)

	// SubscribeToServiceKeySessions subscribes to service key session events.
	// When a service key session is created, updated, or deleted, the event is
	// emitted on the given channel. Cancelling the provided context will unsubscribe from
	// service key session events.
	SubscribeToServiceKeySessions(ctx context.Context) (<-chan *ServiceKeySessionEvent, error)
	// ListServiceKeySessions returns a list of all service key session IDs. If there is an error while
	// listing the service key session IDs, an error is returned. If there is no error, the list
	// of service key session IDs is returned.
	ListServiceKeySessions(ctx context.Context) ([]*servicekey.Session, error)
	// SetServiceKeySession sets the service key session for the given servicekeySession.ID. If
	// there is an error while setting the service key session, an error is returned.
	SetServiceKeySession(ctx context.Context, servicekeySession *servicekey.Session) error
	// GetServiceKeySession returns the service key session for the given servicekeySessionID. If
	// there is an error while getting the service key session, an error is returned.
	// If there is no error, the service key session is returned.
	GetServiceKeySession(ctx context.Context, servicekeySessionID string) (*servicekey.Session, error)
	// DeleteServiceKeySession deletes the service key session for the given servicekeySessionID. If
	// there is an error while deleting the service key session, an error is returned.
	// An error is returned if the service key session does not exist.
	DeleteServiceKeySession(ctx context.Context, servicekeySessionID string) error

	// GetServiceKey returns the service key for the given service key ID. If there is an error
	// while getting the service key, an error is returned. If there is no error, the service key
	// is returned.
	GetServiceKey(ctx context.Context, servicekeyID string) (*servicekey.ServiceKey, error)
	// IncrementServiceKeyNumUsed increments the number of times the service key has been used.
	// If there is an error while incrementing the number of times the service key has been used,
	// an error is returned. If the service key does not exist, an error is returned.
	IncrementServiceKeyNumUsed(ctx context.Context, servicekeyID string) error
}
