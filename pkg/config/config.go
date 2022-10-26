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

package config

import (
	"github.com/joho/godotenv"
	"os"
	"strconv"
)

func init() {
	_ = godotenv.Load()
}

type Config struct {
	Debug       bool     `json:"debug"`
	Listen      string   `json:"listen"`
	Issuer      string   `json:"issuer"`
	TLS         bool     `json:"tls"`
	Database    Database `json:"database"`
	DexDatabase Database `json:"dex_database"`
	OAuth       OAuth    `json:"oauth"`
	Clients     []Client `json:"clients"`
}

type Database struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OAuth struct {
	GithubOAuth GithubOAuth `json:"github"`
}

type GithubOAuth struct {
	Enabled      bool   `json:"enabled"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

type Client struct {
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	RedirectURI string `json:"redirect_uri"`
	Public      bool   `json:"public"`
	Logo        string `json:"logo"`
}

func New() Config {
	debug, err := strconv.ParseBool(os.Getenv("DEBUG"))
	if err != nil {
		debug = false
	}

	listen, exists := os.LookupEnv("LISTEN")
	if !exists {
		listen = ":8080"
	}

	issuer, exists := os.LookupEnv("ISSUER")
	if err != nil {
		issuer = "http://localhost:8080"
	}

	tls, err := strconv.ParseBool(os.Getenv("TLS"))
	if err != nil {
		tls = false
	}

	databaseType, exists := os.LookupEnv("DATABASE_TYPE")
	if !exists {
		databaseType = "sqlite3"
	}

	databaseURL, exists := os.LookupEnv("DATABASE_URL")
	if !exists {
		databaseURL = ":memory:?_fk=1"
	}

	dexDatabaseType, exists := os.LookupEnv("DEX_DATABASE_TYPE")
	if !exists {
		dexDatabaseType = "sqlite3"
	}

	dexDatabaseURL, exists := os.LookupEnv("DEX_DATABASE_URL")
	if !exists {
		dexDatabaseURL = ":memory:?_fk=1"
	}

	oauthGithubEnabled, err := strconv.ParseBool(os.Getenv("OAUTH_GITHUB_ENABLED"))
	if err != nil {
		oauthGithubEnabled = false
	}

	oauthGithubClientID, exists := os.LookupEnv("OAUTH_GITHUB_CLIENT_ID")
	if !exists {
		oauthGithubClientID = ""
	}

	oauthGithubClientSecret, exists := os.LookupEnv("OAUTH_GITHUB_CLIENT_SECRET")
	if !exists {
		oauthGithubClientSecret = ""
	}

	oauthGithubRedirectURI, exists := os.LookupEnv("OAUTH_GITHUB_REDIRECT_URI")
	if !exists {
		oauthGithubRedirectURI = ""
	}

	numClients, err := strconv.Atoi(os.Getenv("NUM_CLIENTS"))
	if err != nil {
		numClients = 0
	}

	clients := make([]Client, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = Client{
			ID:          os.Getenv("CLIENT_" + strconv.Itoa(i) + "_ID"),
			Secret:      os.Getenv("CLIENT_" + strconv.Itoa(i) + "_SECRET"),
			RedirectURI: os.Getenv("CLIENT_" + strconv.Itoa(i) + "_REDIRECT_URI"),
			Public:      os.Getenv("CLIENT_"+strconv.Itoa(i)+"_PUBLIC") == "true",
			Logo:        os.Getenv("CLIENT_" + strconv.Itoa(i) + "_LOGO"),
		}
	}

	return Config{
		Debug:  debug,
		Listen: listen,
		Issuer: issuer,
		TLS:    tls,
		Database: Database{
			Type: databaseType,
			URL:  databaseURL,
		},
		DexDatabase: Database{
			Type: dexDatabaseType,
			URL:  dexDatabaseURL,
		},
		OAuth: OAuth{
			GithubOAuth: GithubOAuth{
				Enabled:      oauthGithubEnabled,
				RedirectURI:  oauthGithubRedirectURI,
				ClientID:     oauthGithubClientID,
				ClientSecret: oauthGithubClientSecret,
			},
		},
		Clients: clients,
	}
}
