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
	"github.com/loopholelabs/auth/pkg/servicekey"
)

type ServiceKey interface {
	// GetServiceKey returns the service key for the given ID. If there is an error
	// while getting the service key, an error is returned. If there is no error, the service key
	// is returned. If the service key does not exist, ErrNotFound is returned.
	GetServiceKey(ctx context.Context, id string) (*servicekey.ServiceKey, error)

	// IncrementServiceKeyNumUsed increments the number of times the service key has been used by increment.
	// If there is an error while incrementing the number of times the service key has been used,
	// an error is returned. If the service key does not exist, ErrNotFound is returned.
	IncrementServiceKeyNumUsed(ctx context.Context, id string, increment int64) error
}
