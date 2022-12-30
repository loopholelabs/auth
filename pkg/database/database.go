/*
	Copyright 2022 Loophole Labs

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

func (d *Database) SetGithubFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string) error {
	_, err := d.client.GithubFlow.Create().SetState(state).SetVerifier(verifier).SetChallenge(challenge).SetNextURL(nextURL).SetOrganization(organization).Save(ctx)
	return err
}

func (d *Database) GetGithubFlow(ctx context.Context, state string) (*ent.GithubFlow, error) {
	return d.client.GithubFlow.Query().Where(githubflow.State(state)).Only(ctx)
}

func (d *Database) DeleteGithubFlow(ctx context.Context, state string) error {
	_, err := d.client.GithubFlow.Delete().Where(githubflow.State(state)).Exec(ctx)
	return err
}

func (d *Database) GCGithubFlow(ctx context.Context, expiry time.Duration) (int, error) {
	return d.client.GithubFlow.Delete().Where(githubflow.CreatedAtLT(time.Now().Add(expiry))).Exec(ctx)
}
