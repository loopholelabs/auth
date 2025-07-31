//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when a key is not found.
	ErrNotFound = errors.New("key not found")

	// ErrAlreadyExists is returned when a key already exists.
	ErrAlreadyExists = errors.New("key already exists")

	ErrRevalidationFailed = errors.New("revalidation failed")
)

// CommonImmutableData is the common immutable data fields stored by Credentials
type CommonImmutableData struct {
	// Identifier is the Credential's unique identifier
	Identifier string `json:"identifier"`

	// Creation is the time at which this Credential was created
	Creation time.Time `json:"creation"`

	// OrganizationIdentifier is the identifier of the Organization that this Credential is scoped to
	OrganizationIdentifier string `json:"organization_identifier"`
}

// CommonMutableData is the common mutable data fields stored by Credentials
type CommonMutableData struct {
	// Generation is the Credential's monotonically increasing generation
	Generation uint64 `json:"generation"`

	// Role is the Credential's role in the Organization that this Credential is scoped to
	Role string `json:"role"`
}

// Credential is the common interface that can be used to interact with
// the various Credential types
type Credential interface {
	ImmutableData() CommonImmutableData
	MutableData(ctx context.Context) (CommonMutableData, error)
	CanAccess(ctx context.Context, resourceIdentifier ResourceIdentifier) bool
}

// UnsafeCredential is the common unsafe interface that can be used to interact with
// the various Credential types
type UnsafeCredential interface {
	ImmutableData() CommonImmutableData
	MutableData() CommonMutableData
}

// InvalidationChecker checks whether a given Credential is invalid
type InvalidationChecker interface {
	// IsInvalid returns true if the given credential is invalid
	IsInvalid(identifier string, generation uint64) bool
}

// Storage is the interface that must be implemented by the application
// using this auth library for authentication and session handling.
type Storage interface {
	User
	SecretKey
	Flow
	Health

	Session
	APIKey
	ServiceKey
	Configuration

	Shutdown() error
}
