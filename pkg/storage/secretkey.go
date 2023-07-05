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
)

// SecretKeyEvent is the event that is emitted when a secret key is rotated, and contains the new secret key.
type SecretKeyEvent [32]byte

// SecretKey is the interface for managing the secret keys used to sign and verify sessions.
type SecretKey interface {
	// SetSecretKey sets the current secret key. If there is an error while
	// setting the secret key, an error is returned.
	// If there is no error, the secret key is returned.
	SetSecretKey(ctx context.Context, secretKey [32]byte) error

	// GetSecretKey returns the current secret key. If there is an error while
	// getting the secret key, an error is returned. If the secret key does not
	// exist, ErrNotFound is returned. If there is no error, the secret
	// key is returned.
	GetSecretKey(ctx context.Context) ([32]byte, error)

	// SubscribeToSecretKey subscribes to secret key events. When the secret key is
	// rotated, the event is emitted on the given channel. Cancelling the provided
	// context will unsubscribe from secret key events.
	//
	// The storage implementation is responsible for ensuring that the channel is not
	// interrupted by network errors, etc. The channel should only be closed
	// when the context is cancelled.
	SubscribeToSecretKey(ctx context.Context) <-chan SecretKeyEvent
}
