/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package storage

import (
	"context"
	"errors"
)

var (
	ErrInvalidSecretKey = errors.New("invalid secret key")
)

// SecretKeyEvent is the event that is emitted when a secret key is rotated
type SecretKeyEvent struct {
	// SecretKey is the new secret key
	SecretKey []byte
}

// SecretKey is the interface for managing the secret keys used to sign and verify sessions.
type SecretKey interface {
	// SetSecretKey sets the current secret key. If there is an error while
	// setting the secret key, an error is returned.
	// If there is no error, the secret key is returned.
	// The secret key should be exactly 32 bytes long. If it
	// is not, ErrInvalidSecretKey is returned.
	SetSecretKey(ctx context.Context, secretKey []byte) error

	// GetSecretKey returns the current secret key. If there is an error while
	// getting the secret key, an error is returned. If the secret key does not
	// exist, ErrNotFound is returned. If there is no error, the secret
	// key is returned. The secret key should be exactly 32 bytes long. If it
	// is not, ErrInvalidSecretKey is returned.
	GetSecretKey(ctx context.Context) ([]byte, error)

	// SubscribeToSecretKey subscribes to secret key events. When the secret key is
	// rotated, the event is emitted on the given channel. Cancelling the provided
	// context will unsubscribe from secret key events.
	SubscribeToSecretKey(ctx context.Context) <-chan *SecretKeyEvent
}
