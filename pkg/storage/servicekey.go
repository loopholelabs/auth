//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"time"
)

var _ Credential = (*ServiceKey)(nil)

// ServiceKeyImmutableData is the ServiceKey's unique immutable data
type ServiceKeyImmutableData struct {
	// Common Immutable Data
	CommonImmutableData

	// Salt is the ServiceKey's salt
	Salt []byte `json:"salt"`

	// Hash is the hashed secret of the ServiceKey
	Hash []byte `json:"hash"`

	// Expiry is the time at which this ServiceKey will expire
	Expiry time.Time `json:"expiry"`
}

// ServiceKeyMutableData is the ServiceKey's unique mutable data
type ServiceKeyMutableData struct {
	// Common Mutable Data
	CommonMutableData

	// ResourceIDs is the list of resources this ServiceKey can access
	ResourceIDs []ResourceIdentifier `json:"resource_ids"`
}

// ServiceKey represents an Service Key Credential
type ServiceKey struct {
	immutableData ServiceKeyImmutableData
	mutableData   ServiceKeyMutableData
}

// NewServiceKey returns a new ServiceKey
func NewServiceKey(immutableData ServiceKeyImmutableData, mutableData ServiceKeyMutableData) ServiceKey {
	return ServiceKey{
		immutableData: immutableData,
		mutableData:   mutableData,
	}
}

// UniqueImmutableData returns the ServiceKey's unique immutable data (which includes the common immutable data)
func (a *ServiceKey) UniqueImmutableData() ServiceKeyImmutableData {
	return a.immutableData
}

// UniqueMutableData returns the ServiceKey's unique mutable data (which includes the common mutable data)
func (a *ServiceKey) UniqueMutableData(_ context.Context) (ServiceKeyMutableData, error) {
	return a.mutableData, nil
}

// ImmutableData returns the ServiceKey's common immutable data
func (a *ServiceKey) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

// MutableData returns the ServiceKey's common mutable data
func (a *ServiceKey) MutableData(ctx context.Context) (CommonMutableData, error) {
	md, err := a.UniqueMutableData(ctx)
	return md.CommonMutableData, err
}

// CanAccess returns whether the ServiceKey can access the given ResourceIdentifier
func (a *ServiceKey) CanAccess(ctx context.Context, resourceIdentifier ResourceIdentifier) bool {
	md, err := a.UniqueMutableData(ctx)
	if err != nil {
		return false
	}
	for _, _resourceIdentifier := range md.ResourceIDs {
		if _resourceIdentifier.Equals(resourceIdentifier) {
			return true
		}
	}
	return false
}

// ServiceKeyReadProvider is the read-only storage interface for ServiceKeys
type ServiceKeyReadProvider interface {
	// GetServiceKey returns the ServiceKey for the given identifier
	//
	// If the ServiceKey does not exist, ErrNotFound is returned
	GetServiceKey(ctx context.Context, identifier string) (ServiceKey, error)

	// ListServiceKeysByOrganization returns a list of all ServiceKeys for a given Organization Identifier
	//
	// If the Organization does not exist, ErrNotFound is returned
	// If there are no ServiceKeys for the Organization, an empty list is returned
	ListServiceKeysByOrganization(ctx context.Context, organizationIdentifier string) ([]ServiceKey, error)
}

// ServiceKeyProvider is the storage interface for ServiceKeys
type ServiceKeyProvider interface {
	// ServiceKeyReadProvider is the read-only storage interfaces for ServiceKeys
	ServiceKeyReadProvider
}
