//SPDX-License-Identifier: Apache-2.0

package storage

import "context"

// Credential is the common interface that can be used to interact with
// the various Credential types
type Credential interface {
	ImmutableData() CommonImmutableData
	MutableData(ctx context.Context) (CommonMutableData, error)
	CanAccess(ctx context.Context, resourceIdentifier ResourceIdentifier) bool
}

// InvalidationChecker checks whether a given Credential is invalid
type InvalidationChecker interface {
	// IsInvalid returns true if the given credential is invalid
	IsInvalid(identifier string, generation uint64) bool
}
