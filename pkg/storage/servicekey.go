//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"time"
)

var _ UnsafeCredential[UnsafeServiceKey, ServiceKey, ServiceKeyImmutableData, ServiceKeyMutableData, ServiceKeyReadProvider] = (*UnsafeServiceKey)(nil)
var _ Credential[UnsafeServiceKey, ServiceKeyImmutableData, ServiceKeyMutableData, ServiceKeyReadProvider] = (*ServiceKey)(nil)

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

// UnsafeServiceKey represents an unsafe Service Key Credential
type UnsafeServiceKey struct {
	// UnsafeServiceKey's immutable data
	immutableData ServiceKeyImmutableData

	// UnsafeServiceKey's mutable data
	mutableData ServiceKeyMutableData
}

// NewUnsafeServiceKey returns a new UnsafeServiceKey
func NewUnsafeServiceKey(immutableData ServiceKeyImmutableData, mutableData ServiceKeyMutableData) UnsafeServiceKey {
	return UnsafeServiceKey{
		immutableData: immutableData,
		mutableData:   mutableData,
	}
}

// Safe returns the Safe Service Key representation
func (a UnsafeServiceKey) Safe(_ ServiceKeyReadProvider, _ InvalidationChecker) ServiceKey {
	return ServiceKey{
		unsafe: a,
	}
}

// SetMutableData sets the Mutable Data for the UnsafeServiceKey
func (a UnsafeServiceKey) SetMutableData(uniqueMutableData ServiceKeyMutableData) UnsafeServiceKey {
	a.mutableData = uniqueMutableData
	return a
}

// UniqueImmutableData returns the UnsafeServiceKey's unique immutable data (which includes the common immutable data)
func (a UnsafeServiceKey) UniqueImmutableData() ServiceKeyImmutableData {
	return a.immutableData
}

// UniqueMutableData returns the UnsafeServiceKey's unique mutable data (which includes the common mutable data)
func (a UnsafeServiceKey) UniqueMutableData() ServiceKeyMutableData {
	return a.mutableData
}

// ImmutableData returns the UnsafeServiceKey's common immutable data
func (a UnsafeServiceKey) ImmutableData() CommonImmutableData {
	return a.UniqueImmutableData().CommonImmutableData
}

// MutableData returns the UnsafeServiceKey's common mutable data
func (a UnsafeServiceKey) MutableData() CommonMutableData {
	return a.UniqueMutableData().CommonMutableData
}

// ServiceKey represents an Service Key Credential
type ServiceKey struct {
	// ServiceKey's unsafe data
	unsafe UnsafeServiceKey
}

// NewServiceKey returns a new ServiceKey
func NewServiceKey(immutableData ServiceKeyImmutableData, mutableData ServiceKeyMutableData) ServiceKey {
	return ServiceKey{
		unsafe: NewUnsafeServiceKey(immutableData, mutableData),
	}
}

// Unsafe returns the Unsafe Service Key representation
func (a *ServiceKey) Unsafe() UnsafeServiceKey {
	return a.unsafe
}

// SetUnsafeMutable sets the UnsafeServiceKey's ServiceKeyMutableData for an ServiceKey
func (a *ServiceKey) SetUnsafeMutable(uniqueMutableData ServiceKeyMutableData) {
	a.unsafe = a.Unsafe().SetMutableData(uniqueMutableData)
}

// UniqueImmutableData returns the ServiceKey's unique immutable data (which includes the common immutable data)
func (a *ServiceKey) UniqueImmutableData() ServiceKeyImmutableData {
	return a.Unsafe().UniqueImmutableData()
}

// UniqueMutableData returns the ServiceKey's unique mutable data (which includes the common mutable data)
func (a *ServiceKey) UniqueMutableData(_ context.Context) (ServiceKeyMutableData, error) {
	return a.Unsafe().UniqueMutableData(), nil
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
