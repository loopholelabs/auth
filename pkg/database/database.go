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
	_ "github.com/lib/pq"
	"github.com/loopholelabs/auth/internal/ent"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
)

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
