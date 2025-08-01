//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"time"

	"github.com/loopholelabs/auth/pkg/flow"
)

var _ UnsafeCredential[UnsafeSession, Session, SessionImmutableData, SessionMutableData, SessionReadProvider] = (*UnsafeSession)(nil)
var _ Credential[UnsafeSession, SessionImmutableData, SessionMutableData, SessionReadProvider] = (*Session)(nil)

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

// UnsafeSession represents an unsafe Session Credential
type UnsafeSession struct {
	// UnsafeSession's immutable data
	immutableData SessionImmutableData

	// UnsafeSession's mutable data
	mutableData SessionMutableData
}

// NewUnsafeSession returns a new UnsafeSession
func NewUnsafeSession(immutableData SessionImmutableData, mutableData SessionMutableData) UnsafeSession {
	return UnsafeSession{
		immutableData: immutableData,
		mutableData:   mutableData,
	}
}

// Safe returns the Safe Session representation
func (a UnsafeSession) Safe(readProvider SessionReadProvider, invalidationChecker InvalidationChecker) Session {
	return Session{
		unsafe:              a,
		readProvider:        readProvider,
		invalidationChecker: invalidationChecker,
	}
}

// SetMutableData sets the Mutable Data for the UnsafeSession
func (a UnsafeSession) SetMutableData(mutableData SessionMutableData) UnsafeSession {
	a.mutableData = mutableData
	return a
}

// UniqueImmutableData returns the UnsafeSession's unique immutable data (which includes the common immutable data)
func (a UnsafeSession) UniqueImmutableData() SessionImmutableData {
	return a.immutableData
}

// UniqueMutableData returns the UnsafeSession's unique mutable data (which includes the common mutable data)
func (a UnsafeSession) UniqueMutableData() SessionMutableData {
	return a.mutableData
}

// ImmutableData returns the UnsafeSession's common immutable data
func (a UnsafeSession) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

// MutableData returns the UnsafeSession's common mutable data
func (a UnsafeSession) MutableData() CommonMutableData {
	return a.UniqueMutableData().CommonMutableData
}

// Session represents a Session Credential
type Session struct {
	// Session's unsafe data
	unsafe UnsafeSession

	// Session's SessionReadProvider
	readProvider SessionReadProvider

	// Session's InvalidationChecker
	invalidationChecker InvalidationChecker
}

// NewSession returns a new Session
func NewSession(immutableData SessionImmutableData, mutableData SessionMutableData, readProvider SessionReadProvider, invalidationChecker InvalidationChecker) Session {
	if readProvider == nil || invalidationChecker == nil {
		panic("ReadProvider and InvalidationChecker must not be nil")
	}
	return Session{
		unsafe:              NewUnsafeSession(immutableData, mutableData),
		readProvider:        readProvider,
		invalidationChecker: invalidationChecker,
	}
}

// Unsafe returns the Unsafe Session representation
func (a *Session) Unsafe() UnsafeSession {
	return a.unsafe
}

// SetUnsafeMutable sets the UnsafeSession's SessionMutableData for a Session
func (a *Session) SetUnsafeMutable(mutableData SessionMutableData) {
	a.unsafe = a.Unsafe().SetMutableData(mutableData)
}

// UniqueImmutableData returns the Session's unique immutable data (which includes the common immutable data)
func (a *Session) UniqueImmutableData() SessionImmutableData {
	return a.Unsafe().UniqueImmutableData()
}

// UniqueMutableData returns the Session's unique mutable data (which includes the common mutable data)
func (a *Session) UniqueMutableData(ctx context.Context) (SessionMutableData, error) {
	if a.invalidationChecker.IsInvalid(a.UniqueImmutableData().Identifier, a.Unsafe().MutableData().Generation) {
		session, err := a.readProvider.GetSession(ctx, a.UniqueImmutableData().UserIdentifier)
		if err != nil {
			return SessionMutableData{}, errors.Join(ErrRevalidationFailed, err)
		}
		a.SetUnsafeMutable(session.Unsafe().UniqueMutableData())
	}
	return a.Unsafe().UniqueMutableData(), nil
}

// ImmutableData returns the Session's common immutable data
func (a *Session) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

// MutableData returns the Session's common mutable data
func (a *Session) MutableData(ctx context.Context) (CommonMutableData, error) {
	md, err := a.UniqueMutableData(ctx)
	return md.CommonMutableData, err
}

// CanAccess returns whether the Session can access the given ResourceIdentifier
func (a *Session) CanAccess(_ context.Context, _ ResourceIdentifier) bool {
	return true
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
	SetSession(ctx context.Context, session Session) error

	// DeleteSession deletes the session for the given id. If
	// there is an error while deleting the session, an error is returned.
	// ErrNotFound is returned if the session does not exist.
	DeleteSession(ctx context.Context, identifier string) error

	// UpdateSessionExpiry updates the expiry of the session for the given id. If
	// there is an error while updating the session, an error is returned. If the
	// session does not exist, ErrNotFound is returned.
	UpdateSessionExpiry(ctx context.Context, identifier string, expiry time.Time) error
}
