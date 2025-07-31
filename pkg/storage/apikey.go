//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
)

var _ Credential = (*APIKey)(nil)

// APIKeyImmutableData is the APIKey's unique immutable data
type APIKeyImmutableData struct {
	// Common Immutable Data
	CommonImmutableData

	// Salt is the APIKey's salt
	Salt []byte `json:"salt"`

	// Hash is the hashed secret of the APIKey
	Hash []byte `json:"hash"`
}

// APIKeyMutableData is the APIKey's unique mutable data
type APIKeyMutableData struct {
	// Common Mutable Data
	CommonMutableData
}

// APIKey represents an API Key Credential
type APIKey struct {
	immutableData APIKeyImmutableData
	mutableData   APIKeyMutableData
}

// NewAPIKey returns a new APIKey
func NewAPIKey(immutableData APIKeyImmutableData, mutableData APIKeyMutableData) APIKey {
	return APIKey{
		immutableData: immutableData,
		mutableData:   mutableData,
	}
}

// UniqueImmutableData returns the APIKey's unique immutable data (which includes the common immutable data)
func (a *APIKey) UniqueImmutableData() APIKeyImmutableData {
	return a.immutableData
}

// UniqueMutableData returns the APIKey's unique mutable data (which includes the common mutable data)
func (a *APIKey) UniqueMutableData(_ context.Context) (APIKeyMutableData, error) {
	return a.mutableData, nil
}

// ImmutableData returns the APIKey's common immutable data
func (a *APIKey) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

// MutableData returns the APIKey's common mutable data
func (a *APIKey) MutableData(ctx context.Context) (CommonMutableData, error) {
	md, err := a.UniqueMutableData(ctx)
	return md.CommonMutableData, err
}

// CanAccess returns whether the APIKey can access the given ResourceIdentifier
func (a *APIKey) CanAccess(_ context.Context, _ ResourceIdentifier) bool {
	return true
}

// APIKeyReadProvider is the read-only storage interface for APIKeys
type APIKeyReadProvider interface {
	// GetAPIKey returns the APIKey for the given identifier
	//
	// If the APIKey does not exist, ErrNotFound is returned
	GetAPIKey(ctx context.Context, identifier string) (APIKey, error)

	// ListAPIKeysByOrganization returns a list of all APIKeys for a given Organization Identifier
	//
	// If the Organization does not exist, ErrNotFound is returned
	// If there are no APIKeys for the Organization, an empty list is returned
	ListAPIKeysByOrganization(ctx context.Context, organizationIdentifier string) ([]APIKey, error)
}

// APIKeyProvider is the storage interface for APIKeys
type APIKeyProvider interface {
	// APIKeyReadProvider is the read-only storage interfaces for APIKeys
	APIKeyReadProvider
}
