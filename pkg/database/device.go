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

package database

import (
	"context"
	"github.com/loopholelabs/auth/internal/ent"
	"github.com/loopholelabs/auth/internal/ent/deviceflow"
	"github.com/loopholelabs/auth/pkg/provider/device"
	"time"
)

var _ device.Database = (*Database)(nil)

func (d *Database) SetDeviceFlow(ctx context.Context, identifier string, deviceCode string, userCode string) error {
	d.logger.Debug().Msgf("setting device flow for %s (device code %s, user code %s)", identifier, deviceCode, userCode)
	_, err := d.client.DeviceFlow.Create().SetIdentifier(identifier).SetDeviceCode(deviceCode).SetUserCode(userCode).Save(ctx)
	return err
}

func (d *Database) GetDeviceFlow(ctx context.Context, deviceCode string) (*ent.DeviceFlow, error) {
	d.logger.Debug().Msgf("getting device flow for device code %s", deviceCode)
	return d.client.DeviceFlow.Query().Where(deviceflow.DeviceCode(deviceCode)).Only(ctx)
}

func (d *Database) UpdateDeviceFlow(ctx context.Context, identifier string, session string, expiry time.Time) error {
	d.logger.Debug().Msgf("updating device flow for %s (expiry %s)", identifier, expiry)
	_, err := d.client.DeviceFlow.Update().Where(deviceflow.Identifier(identifier)).SetSession(session).SetExpiresAt(expiry).Save(ctx)
	return err
}

func (d *Database) GetDeviceFlowUserCode(ctx context.Context, userCode string) (*ent.DeviceFlow, error) {
	d.logger.Debug().Msgf("getting device flow for user code %s", userCode)
	flow, err := d.client.DeviceFlow.Query().Where(deviceflow.UserCode(userCode)).Only(ctx)
	if err != nil {
		return nil, err
	}
	_, err = flow.Update().SetLastPoll(time.Now()).Save(ctx)
	if err != nil {
		return nil, err
	}
	return flow, nil
}

func (d *Database) GetDeviceFlowIdentifier(ctx context.Context, identifier string) (*ent.DeviceFlow, error) {
	d.logger.Debug().Msgf("getting device flow for identifier %s", identifier)
	flow, err := d.client.DeviceFlow.Query().Where(deviceflow.Identifier(identifier)).Only(ctx)
	if err != nil {
		return nil, err
	}
	return flow, nil
}

func (d *Database) DeleteDeviceFlow(ctx context.Context, deviceCode string) error {
	d.logger.Debug().Msgf("deleting device flow for device code %s", deviceCode)
	_, err := d.client.DeviceFlow.Delete().Where(deviceflow.DeviceCode(deviceCode)).Exec(ctx)
	return err
}

func (d *Database) GCDeviceFlow(ctx context.Context, expiry time.Duration) (int, error) {
	d.logger.Debug().Msgf("running device flow gc")
	return d.client.DeviceFlow.Delete().Where(deviceflow.CreatedAtLT(time.Now().Add(expiry))).Exec(ctx)
}
