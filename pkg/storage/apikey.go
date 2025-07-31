//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
)

var _ UnsafeCredential = (*UnsafeAPIKey)(nil)
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

// UnsafeAPIKey represents an unsafe API Key Credential
type UnsafeAPIKey struct {
	// UnsafeAPIKey's immutable data
	immutableData APIKeyImmutableData

	// UnsafeAPIKey's mutable data
	mutableData APIKeyMutableData
}

// NewUnsafeAPIKey returns a new UnsafeAPIKey
func NewUnsafeAPIKey(immutableData APIKeyImmutableData, mutableData APIKeyMutableData) UnsafeAPIKey {
	return UnsafeAPIKey{
		immutableData: immutableData,
		mutableData:   mutableData,
	}
}

// UniqueImmutableData returns the UnsafeAPIKey's unique immutable data (which includes the common immutable data)
func (a UnsafeAPIKey) UniqueImmutableData() APIKeyImmutableData {
	return a.immutableData
}

// UniqueMutableData returns the UnsafeAPIKey's unique mutable data (which includes the common mutable data)
func (a UnsafeAPIKey) UniqueMutableData() APIKeyMutableData {
	return a.mutableData
}

// ImmutableData returns the UnsafeAPIKey's common immutable data
func (a UnsafeAPIKey) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

// MutableData returns the UnsafeAPIKey's common mutable data
func (a UnsafeAPIKey) MutableData() CommonMutableData {
	return a.UniqueMutableData().CommonMutableData
}

func (a UnsafeAPIKey) SetMutableData(uniqueMutableData APIKeyMutableData) UnsafeAPIKey {
	a.mutableData = uniqueMutableData
	return a
}

// APIKey represents an API Key Credential
type APIKey struct {
	// APIKey's unsafe data
	unsafe UnsafeAPIKey
}

// NewAPIKey returns a new APIKey
func NewAPIKey(immutableData APIKeyImmutableData, mutableData APIKeyMutableData) APIKey {
	return APIKey{
		unsafe: NewUnsafeAPIKey(immutableData, mutableData),
	}
}

// Unsafe returns the Unsafe API Key representation
func (a *APIKey) Unsafe() UnsafeAPIKey {
	return a.unsafe
}

// SetUnsafeMutable sets the UnsafeAPIKey's APIKeyMutableData for an APIKey
func (a *APIKey) SetUnsafeMutable(uniqueMutableData APIKeyMutableData) {
	a.unsafe = a.unsafe.SetMutableData(uniqueMutableData)
}

// UniqueImmutableData returns the APIKey's unique immutable data (which includes the common immutable data)
func (a *APIKey) UniqueImmutableData() APIKeyImmutableData {
	return a.Unsafe().UniqueImmutableData()
}

// UniqueMutableData returns the APIKey's unique mutable data (which includes the common mutable data)
func (a *APIKey) UniqueMutableData(_ context.Context) (APIKeyMutableData, error) {
	return a.Unsafe().UniqueMutableData(), nil
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
