//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"time"

	"github.com/loopholelabs/auth/pkg/flow"
)

var _ Credential = (*Session)(nil)

// SessionImmutableData is the Session's unique immutable data
type SessionImmutableData struct {
	// Common Immutable Data
	CommonImmutableData

	// Expiry is the time at which this Session will expire
	Expiry time.Time `json:"expiry"`

	// Provider is the unique provider identifier that was used to create this Session
	Provider flow.Key `json:"provider"`

	// UserIdentifier is the identifier of the User that this Session is scoped to
	UserIdentifier string `json:"user_identifier"`
}

// SessionMutableData is the Session's unique mutable data
type SessionMutableData struct {
	// Common Mutable Data
	CommonMutableData

	// UserEmail is the email of the User that this Session is scoped to
	UserEmail string `json:"user_email"`
}

type Session struct {
	immutableData SessionImmutableData
	mutableData   SessionMutableData

	// If readProvider is nil, assume the mutableData is up-to-date
	readProvider SessionReadProvider

	// invalidationChecker should never be nil
	invalidationChecker InvalidationChecker
}

func NewSession(immutableData SessionImmutableData, mutableData SessionMutableData, invalidationChecker InvalidationChecker) Session {
	return Session{
		immutableData:       immutableData,
		mutableData:         mutableData,
		invalidationChecker: invalidationChecker,
	}
}

func (a *Session) UniqueImmutableData() SessionImmutableData {
	return a.immutableData
}

func (a *Session) UniqueMutableData(ctx context.Context) (SessionMutableData, error) {
	if a.readProvider != nil {
		if a.invalidationChecker == nil {
			panic("invalidation checker is nil")
		}
		if a.invalidationChecker.IsInvalid(a.UniqueImmutableData().Identifier, a.mutableData.Generation) {
			session, err := a.readProvider.GetSession(ctx, a.UniqueImmutableData().UserIdentifier)
			if err != nil {
				return SessionMutableData{}, errors.Join(ErrRevalidationFailed, err)
			}
			a.mutableData = session.mutableData
		}
	}
	return a.mutableData, nil
}

func (a *Session) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

func (a *Session) MutableData(ctx context.Context) (CommonMutableData, error) {
	md, err := a.UniqueMutableData(ctx)
	return md.CommonMutableData, err
}

// SessionReadProvider is the read-only storage interface for sessions
type SessionReadProvider interface {
	// GetSession gets the session for the given identifier.
	//
	// If the session does not exist, ErrNotFound is returned.
	GetSession(ctx context.Context, identifier string) (Session, error)

	// ListSessionsByOrganization returns a list of all sessions for a given
	// Organization Identifier.
	//
	// If the Organization does not exist, ErrNotFound is returned.
	// If there are no sessions for the Organization, an empty list is returned.
	ListSessionsByOrganization(ctx context.Context, organizationIdentifier string) ([]Session, error)

	// ListSessionsByUser returns a list of all sessions for a given User Identifier.
	//
	// If the User does not exist, ErrNotFound is returned.
	// If there are no sessions for the User, an empty list is returned.
	ListSessionsByUser(ctx context.Context, userIdentifier string) ([]Session, error)
}

// SessionProvider is the storage interface for sessions.
type SessionProvider interface {
	// SessionReadProvider is the read-only storage interfaces for sessions
	SessionReadProvider

	// SetSession sets the session for the given session.ID. If there is an error
	// while setting the session, an error is returned.
	// If the user or organization does not exist, ErrNotFound is returned.
	// If the organization associated with the session is not empty, the session is
	// associated with the organization. If the session is associated with an organization
	// and that organization is deleted, the session should also be deleted. If the session
	// already exists, it ErrAlreadyExists is returned.
	SetSession(ctx context.Context, session *Session) error

	// DeleteSession deletes the session for the given id. If
	// there is an error while deleting the session, an error is returned.
	// ErrNotFound is returned if the session does not exist.
	DeleteSession(ctx context.Context, id string) error

	// UpdateSessionExpiry updates the expiry of the session for the given id. If
	// there is an error while updating the session, an error is returned. If the
	// session does not exist, ErrNotFound is returned.
	UpdateSessionExpiry(ctx context.Context, id string, expiry time.Time) error
}
