//SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
)

// Secret represents a 32-byte Secret for Authentication
type Secret [32]byte

// SecretReadProvider is the read-only storage interface for Secrets
type SecretReadProvider interface {
	// GetSecretKey returns the Secret.
	//
	// If the Secret does not exist, ErrNotFound is returned.
	GetSecretKey(ctx context.Context) (Secret, error)
}

// SecretWriteProvider is the write-only storage interface for Secrets
type SecretWriteProvider interface {
	// SetSecretKey sets the Secret.
	SetSecretKey(ctx context.Context, secret Secret) error
}

// SecretProvider is the storage interface for Secrets
type SecretProvider interface {
	// SecretReadProvider is the read-only storage interfaces for Secrets
	SecretReadProvider

	// SecretWriteProvider is the write-only storage interfaces for Secrets
	SecretWriteProvider
}
