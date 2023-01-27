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

package device

import (
	"context"
	"github.com/loopholelabs/auth/internal/ent"
	"time"
)

type Database interface {
	SetDeviceFlow(ctx context.Context, identifier string, deviceCode string, userCode string) error
	GetDeviceFlow(ctx context.Context, deviceCode string) (*ent.DeviceFlow, error)
	UpdateDeviceFlow(ctx context.Context, identifier string, session string, expiry time.Time) error
	GetDeviceFlowUserCode(ctx context.Context, userCode string) (*ent.DeviceFlow, error)
	GetDeviceFlowIdentifier(ctx context.Context, identifier string) (*ent.DeviceFlow, error)
	DeleteDeviceFlow(ctx context.Context, deviceCode string) error
	GCDeviceFlow(ctx context.Context, expiry time.Duration) (int, error)
}
