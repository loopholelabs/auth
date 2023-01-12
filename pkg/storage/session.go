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
	"github.com/loopholelabs/auth/pkg/session"
	"time"
)

// SessionEvent is the event that is triggered when a session is created, updated, or deleted
type SessionEvent struct {
	// ID is the session's unique identifier
	ID string

	// Deleted indicates whether the session was deleted
	Deleted bool

	// Session is the session that was created or updated.
	// If the session was deleted, this will be nil
	Session *session.Session
}

// Session is the interface for storage of sessions.
type Session interface {
	// SetSession sets the session for the given session.ID. If there is an error
	// while setting the session, an error is returned.
	// If the user or organization does not exist, ErrNotFound is returned.
	// If the organization associated with the session is not empty, the session is
	// associated with the organization. If the session is associated with an organization
	// and that organization is deleted, the session should also be deleted. If the session
	// already exists, it ErrAlreadyExists is returned.
	SetSession(ctx context.Context, session *session.Session) error

	// GetSession gets the session for the given id. If there is an error
	// while getting the session, an error is returned. If the session does not
	// exist, ErrNotFound is returned.
	GetSession(ctx context.Context, id string) (*session.Session, error)

	// ListSessions returns a list of all sessions. If there is an error while
	// listing the sessions, an error is returned.
	// If there is no error, the list of sessions is returned.
	ListSessions(ctx context.Context) ([]*session.Session, error)

	// DeleteSession deletes the session for the given id. If
	// there is an error while deleting the session, an error is returned.
	// ErrNotFound is returned if the session does not exist.
	DeleteSession(ctx context.Context, id string) error

	// UpdateSessionExpiry updates the expiry of the session for the given id. If
	// there is an error while updating the session, an error is returned. If the
	// session does not exist, ErrNotFound is returned.
	UpdateSessionExpiry(ctx context.Context, id string, expiry time.Time) error

	// SubscribeToSessions subscribes to session events. When a session is created,
	// updated, or deleted, the event is emitted on the given channel. Cancelling
	// the provided context will unsubscribe from session events.
	SubscribeToSessions(ctx context.Context) <-chan *SessionEvent
}
