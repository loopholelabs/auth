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

package main

import (
	"errors"
	dexStorage "github.com/dexidp/dex/storage"
	"github.com/loopholelabs/auth/pkg/config"
	"github.com/loopholelabs/auth/pkg/options"
	"github.com/loopholelabs/auth/pkg/providers"
	"github.com/loopholelabs/auth/pkg/server"
	database "github.com/loopholelabs/auth/pkg/storage/default"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	logger.Info("Starting Auth Server")
	conf := config.New()

	logger.Infof("Config: %+v", conf)

	d, err := database.New(conf.Database.Type, conf.Database.URL, conf.DexDatabase.Type, conf.DexDatabase.URL, logrus.NewEntry(logger).WithField("COMPONENT", "DATABASE"))
	if err != nil {
		panic(err)
	}

	var gh *providers.GithubProvider
	if conf.OAuth.GithubOAuth.Enabled {
		gh = &providers.GithubProvider{
			ID:           "github",
			ClientID:     conf.OAuth.GithubOAuth.ClientID,
			ClientSecret: conf.OAuth.GithubOAuth.ClientSecret,
			RedirectURI:  conf.OAuth.GithubOAuth.RedirectURI,
		}
	}
	err = server.BootstrapConnectors(d, gh)
	if err != nil {
		panic(err)
	}

	o := &options.Options{
		Issuer:         conf.Issuer,
		AllowedOrigins: []string{"*"},
		Storage:        d,
		Logger:         logrus.New(),
		NewUser:        d.NewUser,
	}

	s, err := server.New(o)
	if err != nil {
		panic(err)
	}

	for _, c := range conf.Clients {
		err = server.CreateClient(d, c.ID, c.Secret, []string{c.RedirectURI}, c.Public, c.ID, c.Logo)
		if err != nil {
			if errors.Is(err, dexStorage.ErrAlreadyExists) {
				cl, err := server.GetClient(d, c.ID)
				if err != nil {
					panic(err)
				}
				if cl.Secret != c.Secret || len(cl.RedirectURIs) != 1 || cl.RedirectURIs[0] != c.RedirectURI || cl.Public != c.Public || cl.LogoURL != c.Logo {
					err = server.UpdateClient(d, c.ID, c.Secret, []string{c.RedirectURI}, c.Public, c.ID, c.Logo)
					if err != nil {
						panic(err)
					}
				}
			} else {
				panic(err)
			}
		}
	}

	err = s.App().Listen(conf.Listen)
	if err != nil {
		panic(err)
	}
}
