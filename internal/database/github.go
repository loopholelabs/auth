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
	"github.com/loopholelabs/auth/internal/ent/githubflow"
	"github.com/loopholelabs/auth/internal/provider/github"
	"time"
)

var _ github.Database = (*Database)(nil)

func (d *Database) SetGithubFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string, deviceIdentifier string) error {
	d.logger.Debug().Msgf("setting github flow for %s", state)
	_, err := d.client.GithubFlow.Create().SetIdentifier(state).SetVerifier(verifier).SetChallenge(challenge).SetNextURL(nextURL).SetOrganization(organization).SetDeviceIdentifier(deviceIdentifier).Save(ctx)
	return err
}

func (d *Database) GetGithubFlow(ctx context.Context, state string) (*ent.GithubFlow, error) {
	d.logger.Debug().Msgf("getting github flow for %s", state)
	return d.client.GithubFlow.Query().Where(githubflow.Identifier(state)).Only(ctx)
}

func (d *Database) DeleteGithubFlow(ctx context.Context, state string) error {
	d.logger.Debug().Msgf("deleting github flow for %s", state)
	_, err := d.client.GithubFlow.Delete().Where(githubflow.Identifier(state)).Exec(ctx)
	return err
}

func (d *Database) GCGithubFlow(ctx context.Context, expiry time.Duration) (int, error) {
	d.logger.Debug().Msgf("running github flow gc")
	return d.client.GithubFlow.Delete().Where(githubflow.CreatedAtLT(time.Now().Add(expiry * -1))).Exec(ctx)
}
