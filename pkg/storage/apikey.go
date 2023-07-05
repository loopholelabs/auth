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
	"github.com/loopholelabs/auth/pkg/apikey"
)

// APIKeyEvent is the event that is emitted when an API key is created, updated, or deleted
type APIKeyEvent struct {
	// ID is the API Key Identifier
	ID string

	// Deleted indicates whether the API Key was deleted
	Deleted bool

	// APIKey is the API Key that was created or updated.
	// If the API Key was deleted, this will be nil
	APIKey *apikey.APIKey
}

// APIKey is the interface for storage of API Keys.
type APIKey interface {
	// GetAPIKey returns the API key for the given identifier. If
	// there is an error while getting the API key, an error is returned.
	// If there is no error, the API key is returned. If the API key does not
	// exist, ErrNotFound is returned.
	GetAPIKey(ctx context.Context, identifier string) (*apikey.APIKey, error)

	// ListAPIKeys returns a list of all API Keys. If there is an error while
	// listing the API keys, an error is returned. If there is no error, the list
	// of API keys is returned. If there are no API keys, an empty list is returned.
	ListAPIKeys(ctx context.Context) ([]*apikey.APIKey, error)

	// SubscribeToAPIKeys subscribes to API key events. When an API key is created,
	// updated, or deleted, the event is emitted on the given channel. Cancelling
	// the provided context will unsubscribe from API key events.
	//
	// The storage implementation is responsible for ensuring that the channel is not
	// interrupted by network errors, etc. The channel should only be closed
	// when the context is cancelled.
	SubscribeToAPIKeys(ctx context.Context) <-chan *APIKeyEvent
}
