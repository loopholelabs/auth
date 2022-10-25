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

package providers

import (
	"github.com/dexidp/dex/connector/github"
)

type GithubProvider struct {
	ID           string `json:"id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
}

func (g *GithubProvider) Validate() bool {
	return g.ClientID != "" && g.ClientSecret != "" && g.RedirectURI != ""
}

func (g *GithubProvider) Populate(conf *github.Config) {
	g.ClientID = conf.ClientID
	g.ClientSecret = conf.ClientSecret
	g.RedirectURI = conf.RedirectURI
}

func (g *GithubProvider) Convert() *github.Config {
	return &github.Config{
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		RedirectURI:  g.RedirectURI,
	}
}
