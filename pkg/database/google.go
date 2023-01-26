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
	"github.com/loopholelabs/auth/internal/ent/googleflow"
	"github.com/loopholelabs/auth/pkg/provider/google"
	"time"
)

var _ google.Database = (*Database)(nil)

func (d *Database) SetGoogleFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string, deviceIdentifier string) error {
	d.logger.Debug().Msgf("setting google flow for %s", state)
	_, err := d.client.GoogleFlow.Create().SetState(state).SetVerifier(verifier).SetChallenge(challenge).SetNextURL(nextURL).SetOrganization(organization).SetDeviceIdentifier(deviceIdentifier).Save(ctx)
	return err
}

func (d *Database) GetGoogleFlow(ctx context.Context, state string) (*ent.GoogleFlow, error) {
	d.logger.Debug().Msgf("getting google flow for %s", state)
	return d.client.GoogleFlow.Query().Where(googleflow.State(state)).Only(ctx)
}

func (d *Database) DeleteGoogleFlow(ctx context.Context, state string) error {
	d.logger.Debug().Msgf("deleting google flow for %s", state)
	_, err := d.client.GoogleFlow.Delete().Where(googleflow.State(state)).Exec(ctx)
	return err
}

func (d *Database) GCGoogleFlow(ctx context.Context, expiry time.Duration) (int, error) {
	d.logger.Debug().Msgf("running google flow gc")
	return d.client.GoogleFlow.Delete().Where(googleflow.CreatedAtLT(time.Now().Add(expiry))).Exec(ctx)
}
