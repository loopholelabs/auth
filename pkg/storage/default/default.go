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
	"entgo.io/ent/dialect"
	"fmt"
	"github.com/dexidp/dex/pkg/log"
	dexStorage "github.com/dexidp/dex/storage"
	dexSQL "github.com/dexidp/dex/storage/sql"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/auth/pkg/storage/default/ent"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/apikey"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/servicekey"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/user"
	"github.com/loopholelabs/auth/pkg/token/identity"
	"net"
	nurl "net/url"
	"strconv"
	"strings"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var _ storage.Storage = (*Default)(nil)

type Default struct {
	client *ent.Client
	dexStorage.Storage
}

func New(connector string, url string, logger log.Logger) (*Default, error) {
	client, err := ent.Open(connector, url)
	if err != nil {
		return nil, err
	}

	err = client.Schema.Create(context.Background())
	if err != nil {
		return nil, err
	}

	var st dexStorage.Storage
	switch connector {
	case dialect.Postgres:
		parsed, err := parsePG(url)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(parsed["port"])
		if err != nil {
			return nil, err
		}
		pg := dexSQL.Postgres{
			NetworkDB: dexSQL.NetworkDB{
				Database: parsed["dbname"],
				User:     parsed["user"],
				Password: parsed["password"],
				Host:     parsed["host"],
				Port:     uint16(port),
			},
			SSL: dexSQL.SSL{
				Mode:   parsed["sslmode"],
				CAFile: parsed["sslrootcert"],
			},
		}

		st, err = pg.Open(logger)
		if err != nil {
			return nil, err
		}
	case dialect.SQLite:
		s := dexSQL.SQLite3{
			File: url,
		}

		st, err = s.Open(logger)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported connector %s", connector)
	}

	return &Default{
		client:  client,
		Storage: st,
	}, nil
}

func (d *Default) UserExists(id string) (bool, error) {
	return d.client.User.Query().Where(user.Username(id)).Exist(context.Background())
}

func (d *Default) GetAPIKey(id string) (*storage.APIKey, error) {
	a, err := d.client.APIKey.Query().Where(apikey.Value(id)).Only(context.Background())
	if err != nil {
		return nil, err
	}

	u, err := a.QueryOwner().Only(context.Background())
	if err != nil {
		return nil, err
	}

	return &storage.APIKey{
		Created: a.CreatedAt,
		ID:      a.Value,
		Secret:  a.Secret,
		User:    u.Username,
	}, nil
}

func (d *Default) CreateAPIKey(key *storage.APIKey) error {
	u, err := d.client.User.Query().Where(user.Username(key.User)).Only(context.Background())
	if err != nil {
		return err
	}
	_, err = d.client.APIKey.Create().SetOwner(u).SetValue(key.ID).SetSecret(key.Secret).Save(context.Background())
	return err
}

func (d *Default) GetServiceKey(id string, valid storage.ServiceKeyValid, update storage.ServiceKeyUpdate) (*storage.ServiceKey, error) {
	s, err := d.client.ServiceKey.Query().Where(servicekey.Value(id)).Only(context.Background())
	if err != nil {
		return nil, err
	}

	u, err := s.QueryOwner().Only(context.Background())
	if err != nil {
		return nil, err
	}

	sk := &storage.ServiceKey{
		Created:  s.CreatedAt,
		ID:       s.Value,
		Secret:   s.Secret,
		User:     u.Username,
		Resource: s.Resource,
		NumUsed:  s.NumUsed,
		MaxUses:  s.MaxUses,
		Expires:  s.Expires,
	}

	if valid != nil {
		err = valid(sk)
		if err != nil {
			return nil, err
		}
	}

	if update != nil {
		update(sk)

		_, err = d.client.ServiceKey.UpdateOne(s).SetResource(sk.Resource).SetNumUsed(sk.NumUsed).SetMaxUses(sk.MaxUses).SetExpires(sk.Expires).Save(context.Background())
		if err != nil {
			return nil, err
		}
	}

	return sk, nil
}

func (d *Default) CreateServiceKey(key *storage.ServiceKey) error {
	u, err := d.client.User.Query().Where(user.Username(key.User)).Only(context.Background())
	if err != nil {
		return err
	}
	_, err = d.client.ServiceKey.Create().SetOwner(u).SetValue(key.ID).SetSecret(key.Secret).SetResource(key.Resource).SetNumUsed(key.NumUsed).SetMaxUses(key.MaxUses).SetExpires(key.Expires).Save(context.Background())
	return err
}

func (d *Default) NewUser(claims *identity.IDToken) error {
	_, err := d.client.User.Create().SetUsername(claims.Email).Save(context.Background())
	return err
}

func (d *Default) Shutdown() error {
	err := d.Storage.Close()
	if err != nil {
		return err
	}
	return d.client.Close()
}

func parsePG(url string) (map[string]string, error) {
	values := make(map[string]string)
	u, err := nurl.Parse(url)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("invalid connection protocol: %s", u.Scheme)
	}

	escaper := strings.NewReplacer(`'`, `\'`, `\`, `\\`)
	accrue := func(k, v string) {
		if v != "" {
			values[k] = escaper.Replace(v)
		}
	}

	if u.User != nil {
		v := u.User.Username()
		accrue("user", v)

		v, _ = u.User.Password()
		accrue("password", v)
	}

	if host, port, err := net.SplitHostPort(u.Host); err != nil {
		accrue("host", u.Host)
	} else {
		accrue("host", host)
		accrue("port", port)
	}

	if u.Path != "" {
		accrue("dbname", u.Path[1:])
	}

	q := u.Query()
	for k := range q {
		accrue(k, q.Get(k))
	}

	return values, nil
}
