//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
)

var _ Credential = (*APIKey)(nil)

// APIKeyImmutableData is the API Key's unique immutable data
type APIKeyImmutableData struct {
	// Common Immutable Data
	CommonImmutableData

	// Salt is the API Key's salt
	Salt []byte `json:"salt"`

	// Hash is the hashed secret of the API Key
	Hash []byte `json:"hash"`
}

// APIKeyMutableData is teh API Key's unique mutable data
type APIKeyMutableData struct {
	// Common Mutable Data
	CommonMutableData
}

type APIKey struct {
	immutableData APIKeyImmutableData
	mutableData   APIKeyMutableData
}

func NewAPIKey(immutableData APIKeyImmutableData, mutableData APIKeyMutableData) APIKey {
	return APIKey{
		immutableData: immutableData,
		mutableData:   mutableData,
	}
}

// UniqueImmutableData returns the API Key's unique immutable data
func (a *APIKey) UniqueImmutableData() APIKeyImmutableData {
	return a.immutableData
}

// UniqueMutableData returns the API Key's unique mutable data
func (a *APIKey) UniqueMutableData() APIKeyMutableData {
	return a.mutableData
}

// ImmutableData returns the API Key's common immutable data
func (a *APIKey) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

// MutableData returns the API Key's common mutable data
func (a *APIKey) MutableData() CommonMutableData {
	return a.UniqueMutableData().CommonMutableData
}

// APIKeyReadProvider is the read-only storage interface for API Keys
type APIKeyReadProvider interface {
	// GetAPIKey returns the API key for the given identifier
	//
	// If the API key does not exist, ErrNotFound is returned
	GetAPIKey(ctx context.Context, identifier string) (APIKey, error)

	// ListAPIKeysByOrganization returns a list of all API Keys for a given Organization Identifier
	//
	// If the Organization does not exist, ErrNotFound is returned
	// If there are no API Keys for the Organization, an empty list is returned
	ListAPIKeysByOrganization(ctx context.Context, organizationIdentifier string) ([]APIKey, error)
}

// APIKeyProvider is the storage interface for API Keys
type APIKeyProvider interface {
	// APIKeyReadProvider is the read-only storage interfaces for API Keys
	APIKeyReadProvider
}
