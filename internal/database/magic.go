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
	"github.com/loopholelabs/auth/internal/ent/magicflow"
	"github.com/loopholelabs/auth/internal/provider/magic"
	"time"
)

var _ magic.Database = (*Database)(nil)

func (d *Database) SetMagicFlow(ctx context.Context, email string, ip string, secret string, nextURL string, organization string, deviceIdentifier string) error {
	d.logger.Debug().Msgf("setting magic flow for %s", email)
	_, err := d.client.MagicFlow.Create().SetEmail(email).SetIPAddress(ip).SetSecret(secret).SetNextURL(nextURL).SetOrganization(organization).SetDeviceIdentifier(deviceIdentifier).Save(ctx)
	return err
}

func (d *Database) GetMagicFlow(ctx context.Context, email string) (*ent.MagicFlow, error) {
	d.logger.Debug().Msgf("getting magic flow for %s", email)
	return d.client.MagicFlow.Query().Where(magicflow.Email(email)).Only(ctx)
}

func (d *Database) DeleteMagicFlow(ctx context.Context, email string) error {
	d.logger.Debug().Msgf("deleting magic flow for %s", email)
	_, err := d.client.MagicFlow.Delete().Where(magicflow.Email(email)).Exec(ctx)
	return err
}

func (d *Database) GCMagicFlow(ctx context.Context, expiry time.Duration) (int, error) {
	d.logger.Debug().Msgf("running magic flow gc")
	return d.client.MagicFlow.Delete().Where(magicflow.CreatedAtLT(time.Now().Add(expiry * -1))).Exec(ctx)
}
