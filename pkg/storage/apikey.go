//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
)

type APIKeyImmutableData struct {
	// Common Immutable Data
	CommonImmutableData

	// Salt is the API Key's salt
	Salt []byte `json:"salt"`

	// Hash is the hashed secret of the API Key
	Hash []byte `json:"hash"`
}

type APIKey struct {
	immutableData APIKeyImmutableData
}

func NewAPIKey(immutableData APIKeyImmutableData) APIKey {
	return APIKey{
		immutableData: immutableData,
	}
}

func (api *APIKey) ImmutableData() APIKeyImmutableData {
	return api.immutableData
}

// APIKeyReadProvider is the read-only storage interface for API Keys.
type APIKeyReadProvider interface {
	// GetAPIKey returns the API key for the given identifier.
	//
	// If the API key does not exist, ErrNotFound is returned.
	GetAPIKey(ctx context.Context, identifier string) (APIKey, error)

	// ListAPIKeysByOrganization returns a list of all API Keys for a given Organization Identifier.
	//
	// If the Organization does not exist, ErrNotFound is returned.
	// If there are no API Keys for the Organization, an empty list is returned.
	ListAPIKeysByOrganization(ctx context.Context, organizationIdentifier string) ([]APIKey, error)
}

// APIKeyProvider is the storage interface for API Keys.
type APIKeyProvider interface {
	APIKeyReadProvider
}
