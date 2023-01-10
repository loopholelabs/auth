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

import "context"

// RegistrationEvent is the event that is emitted when registration is enabled or disabled
type RegistrationEvent struct {
	// Enabled indicates whether registration is enabled
	Enabled bool
}

// Registration is the interface for storage of registration settings.
type Registration interface {
	// SetRegistration sets whether registration is enabled. If there is an error
	// while setting the registration status, an error is returned.
	SetRegistration(ctx context.Context, enabled bool) error

	// GetRegistration returns whether registration is enabled. If there is an error
	// while getting the registration status, an error is returned. If there is no
	// error, the boolean indicates whether registration is enabled.
	GetRegistration(ctx context.Context) (bool, error)

	// SubscribeToRegistration subscribes to registration events. When registration
	// is enabled or disabled, the event is emitted on the given channel. Cancelling
	// the provided context will unsubscribe from registration events.
	SubscribeToRegistration(ctx context.Context) <-chan *RegistrationEvent
}
