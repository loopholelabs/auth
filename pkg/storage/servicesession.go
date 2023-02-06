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
	"github.com/loopholelabs/auth/pkg/servicesession"
)

// ServiceSessionEvent is the event that is triggered when a service session is created, updated, or deleted
type ServiceSessionEvent struct {
	// ID is the service session's unique identifier
	ID string

	// Deleted indicates whether the service session was deleted
	Deleted bool

	// ServiceSession is the service session that was created or updated.
	// If the service session was deleted, this will be nil
	ServiceSession *servicesession.ServiceSession
}

type ServiceSession interface {
	// SetServiceSession sets the service session for the given serviceSession.ID. If
	// there is an error while setting the service session, an error is returned.
	// If the user or organization does not exist, ErrNotFound is returned.
	// If the organization associated with the service session is not empty,
	// service the session is associated with the organization. If the service session is
	// associated with an organization and that organization is deleted, the service session
	// should also be deleted. If the service session already exists, it ErrAlreadyExists is returned.
	SetServiceSession(ctx context.Context, id string, salt []byte, hash []byte, serviceKeyID string) error

	// GetServiceSession gets the service session for the given id. If there is an error
	// while getting the service session, an error is returned. If the service session does not
	// exist, ErrNotFound is returned.
	GetServiceSession(ctx context.Context, id string) (*servicesession.ServiceSession, error)

	// ListServiceSessions returns a list of all service sessions. If there is an error while
	// listing the service sessions, an error is returned.
	// If there is no error, the list of service sessions is returned.
	ListServiceSessions(ctx context.Context) ([]*servicesession.ServiceSession, error)

	// DeleteServiceSession deletes the service session for the given id. If
	// there is an error while deleting the service session, an error is returned.
	// ErrNotFound is returned if the service session does not exist.
	DeleteServiceSession(ctx context.Context, id string) error

	// SubscribeToServiceSessions subscribes to service session events. When a service session is created,
	// updated, or deleted, the event is emitted on the given channel. Cancelling
	// the provided context will unsubscribe from service session events.
	SubscribeToServiceSessions(ctx context.Context) <-chan *ServiceSessionEvent
}
