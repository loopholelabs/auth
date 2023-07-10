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
	"github.com/loopholelabs/auth/pkg/flow"
	"time"
)

type Device interface {
	SetDeviceFlow(ctx context.Context, identifier string, deviceCode string, userCode string) error
	GetDeviceFlow(ctx context.Context, deviceCode string) (*flow.Device, error)
	UpdateDeviceFlow(ctx context.Context, identifier string, sessionID string, encryptedSession string, expiry time.Time) error
	GetDeviceFlowUserCode(ctx context.Context, userCode string) (*flow.Device, error)
	GetDeviceFlowIdentifier(ctx context.Context, identifier string) (*flow.Device, error)
	DeleteDeviceFlow(ctx context.Context, deviceCode string) error
	GCDeviceFlow(ctx context.Context, expiry time.Duration) (int, error)
}

type Github interface {
	SetGithubFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string, deviceIdentifier string) error
	GetGithubFlow(ctx context.Context, state string) (*flow.Github, error)
	DeleteGithubFlow(ctx context.Context, state string) error
	GCGithubFlow(ctx context.Context, expiry time.Duration) (int, error)
}

type Google interface {
	SetGoogleFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string, deviceIdentifier string) error
	GetGoogleFlow(ctx context.Context, state string) (*flow.Google, error)
	DeleteGoogleFlow(ctx context.Context, state string) error
	GCGoogleFlow(ctx context.Context, expiry time.Duration) (int, error)
}

type Magic interface {
	SetMagicFlow(ctx context.Context, email string, salt []byte, hash []byte, ip string, nextURL string, organization string, deviceIdentifier string) error
	GetMagicFlow(ctx context.Context, email string) (*flow.Magic, error)
	DeleteMagicFlow(ctx context.Context, email string) error
	GCMagicFlow(ctx context.Context, expiry time.Duration) (int, error)
}

// Flow is the interface for storage of Authorization Flows
type Flow interface {
	Device
	Github
	Google
	Magic
}
