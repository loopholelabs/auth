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

package config

import (
	"errors"
	"github.com/loopholelabs/auth/pkg/manager"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	ErrListenAddressRequired  = errors.New("listen address is required")
	ErrEndpointRequired       = errors.New("endpoint is required")
	ErrSessionDomainRequired  = errors.New("session domain is required")
	ErrDefaultNextURLRequired = errors.New("default next url is required")
)

const (
	DefaultListenAddress = "127.0.0.1:8081"
	DefaultEndpoint      = "localhost:8081"
	DefaultSessionDomain = "localhost"
	DefaultNextURL       = "https://loopholelabs.io"
)

type Config struct {
	ListenAddress  string `yaml:"listen_address"`
	Endpoint       string `yaml:"endpoint"`
	SessionDomain  string `yaml:"session_domain"`
	DefaultNextURL string `yaml:"default_next_url"`

	GithubClientID     string `yaml:"github_client_id"`
	GithubClientSecret string `yaml:"github_client_secret"`
	GoogleClientID     string `yaml:"github_client_id"`
	GoogleClientSecret string `yaml:"github_client_secret"`
	DeviceCode         bool   `yaml:"device"`
	PostmarkAPIToken   string `yaml:"postmark_api_token"`
	PostmarkTemplateID int    `yaml:"postmark_template_id"`
	PostmarkTag        string `yaml:"postmark_tag"`
	MagicLinkFrom      string `yaml:"magic_link_from"`
}

func New() *Config {
	return &Config{
		ListenAddress:  DefaultListenAddress,
		Endpoint:       DefaultEndpoint,
		SessionDomain:  DefaultSessionDomain,
		DefaultNextURL: DefaultNextURL,
	}
}

func (c *Config) Validate() error {
	if c.ListenAddress == "" {
		return ErrListenAddressRequired
	}
	if c.Endpoint == "" {
		return ErrEndpointRequired
	}
	if c.SessionDomain == "" {
		return ErrSessionDomainRequired
	}
	if c.DefaultNextURL == "" {
		return ErrDefaultNextURLRequired
	}
	return nil
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.StringVar(&c.ListenAddress, "auth-listen-address", DefaultListenAddress, "The auth api's listen address")
	flags.StringVar(&c.Endpoint, "auth-endpoint", DefaultEndpoint, "The auth api's endpoint")
	flags.StringVar(&c.SessionDomain, "auth-session-domain", DefaultSessionDomain, "The auth api's session domain")
	flags.StringVar(&c.DefaultNextURL, "auth-default-next-url", DefaultNextURL, "The auth api's default next url")

	flags.StringVar(&c.GithubClientID, "auth-github-client-id", "", "The auth api's github client id")
	flags.StringVar(&c.GithubClientSecret, "auth-github-client-secret", "", "The auth api's github client secret")
	flags.StringVar(&c.GoogleClientID, "auth-google-client-id", "", "The auth api's google client id")
	flags.StringVar(&c.GoogleClientSecret, "auth-google-client-secret", "", "The auth api's google client secret")
	flags.BoolVar(&c.DeviceCode, "auth-device-code", false, "The whether to enable the auth api's device code provider")
	flags.StringVar(&c.PostmarkAPIToken, "auth-postmark-api-token", "", "The auth api's postmark api token")
	flags.IntVar(&c.PostmarkTemplateID, "auth-postmark-template-id", 0, "The auth api's postmark template id")
	flags.StringVar(&c.PostmarkTag, "auth-postmark-tag", "", "The auth api's postmark tag")
	flags.StringVar(&c.MagicLinkFrom, "auth-magic-link-from", "", "The auth api's magic link from field")
}

func (c *Config) GlobalRequiredFlags(cmd *cobra.Command) error {
	return nil
}

func (c *Config) GenerateOptions(storage storage.Storage, tls bool, projectName string, projectURL string) *manager.Options {
	return &manager.Options{
		Endpoint:             c.Endpoint,
		TLS:                  tls,
		SessionDomain:        c.SessionDomain,
		DefaultNextURL:       c.DefaultNextURL,
		Storage:              storage,
		GithubClientID:       c.GithubClientID,
		GithubClientSecret:   c.GithubClientSecret,
		GoogleClientID:       c.GoogleClientID,
		GoogleClientSecret:   c.GoogleClientSecret,
		DeviceCode:           c.DeviceCode,
		PostmarkAPIToken:     c.PostmarkAPIToken,
		PostmarkTemplateID:   c.PostmarkTemplateID,
		PostmarkTag:          c.PostmarkTag,
		MagicLinkFrom:        c.MagicLinkFrom,
		MagicLinkProjectName: projectName,
		MagicLinkProjectURL:  projectURL,
	}
}
