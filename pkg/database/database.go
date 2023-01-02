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
	"github.com/loopholelabs/auth/ent"
	"github.com/loopholelabs/auth/ent/deviceflow"
	"github.com/loopholelabs/auth/ent/githubflow"
	"github.com/loopholelabs/auth/pkg/provider/github"
	"github.com/rs/zerolog"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var _ github.Database = (*Database)(nil)

type Database struct {
	logger *zerolog.Logger
	client *ent.Client
	ctx    context.Context
	cancel context.CancelFunc
}

func New(connector string, url string, logger *zerolog.Logger) (*Database, error) {
	l := logger.With().Str("AUTH", "DATABASE").Logger()

	l.Debug().Msgf("connecting to %s (%s)", url, connector)
	client, err := ent.Open(connector, url)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	l.Info().Msg("running database migrations")
	err = client.Schema.Create(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Database{
		logger: &l,
		client: client,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (d *Database) Shutdown() error {
	if d.cancel != nil {
		d.cancel()
	}

	if d.client != nil {
		err := d.client.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) SetGithubFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string, deviceIdentifier string) error {
	d.logger.Debug().Msgf("setting github flow for %s", state)
	_, err := d.client.GithubFlow.Create().SetState(state).SetVerifier(verifier).SetChallenge(challenge).SetNextURL(nextURL).SetOrganization(organization).SetDeviceIdentifier(deviceIdentifier).Save(ctx)
	return err
}

func (d *Database) GetGithubFlow(ctx context.Context, state string) (*ent.GithubFlow, error) {
	d.logger.Debug().Msgf("getting github flow for %s", state)
	return d.client.GithubFlow.Query().Where(githubflow.State(state)).Only(ctx)
}

func (d *Database) DeleteGithubFlow(ctx context.Context, state string) error {
	d.logger.Debug().Msgf("deleting github flow for %s", state)
	_, err := d.client.GithubFlow.Delete().Where(githubflow.State(state)).Exec(ctx)
	return err
}

func (d *Database) GCGithubFlow(ctx context.Context, expiry time.Duration) (int, error) {
	d.logger.Debug().Msgf("running github flow gc")
	return d.client.GithubFlow.Delete().Where(githubflow.CreatedAtLT(time.Now().Add(expiry))).Exec(ctx)
}

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

func (d *Database) DeleteDeviceFlow(ctx context.Context, deviceCode string) error {
	d.logger.Debug().Msgf("deleting device flow for device code %s", deviceCode)
	_, err := d.client.DeviceFlow.Delete().Where(deviceflow.DeviceCode(deviceCode)).Exec(ctx)
	return err
}

func (d *Database) GCDeviceFlow(ctx context.Context, expiry time.Duration) (int, error) {
	d.logger.Debug().Msgf("running device flow gc")
	return d.client.DeviceFlow.Delete().Where(deviceflow.CreatedAtLT(time.Now().Add(expiry))).Exec(ctx)
}
