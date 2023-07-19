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
	"github.com/loopholelabs/auth"
	"github.com/spf13/pflag"
)

var (
	ErrListenAddressRequired  = errors.New("listen address is required")
	ErrEndpointRequired       = errors.New("endpoint is required")
	ErrSessionDomainRequired  = errors.New("session domain is required")
	ErrDefaultNextURLRequired = errors.New("default next url is required")
)

const (
	DefaultDisabled      = false
	DefaultListenAddress = "127.0.0.1:8081"
	DefaultEndpoint      = "localhost:8081"
	DefaultSessionDomain = "localhost"
	DefaultNextURL       = "https://loopholelabs.io"
)

type Config struct {
	Disabled             bool   `yaml:"disabled"`
	ListenAddress        string `yaml:"listen_address"`
	Endpoint             string `yaml:"endpoint"`
	TLS                  bool   `yaml:"tls"`
	SessionDomain        string `yaml:"session_domain"`
	DefaultNextURL       string `yaml:"default_next_url"`
	GithubClientID       string `yaml:"github_client_id"`
	GithubClientSecret   string `yaml:"github_client_secret"`
	GoogleClientID       string `yaml:"github_client_id"`
	GoogleClientSecret   string `yaml:"github_client_secret"`
	DeviceCode           bool   `yaml:"device"`
	PostmarkAPIToken     string `yaml:"postmark_api_token"`
	PostmarkTemplateID   int    `yaml:"postmark_template_id"`
	PostmarkTag          string `yaml:"postmark_tag"`
	MagicLinkFrom        string `yaml:"magic_link_from"`
	MagicLinkProjectName string `yaml:"magic_link_project_name"`
	MagicLinkProjectURL  string `yaml:"magic_link_project_url"`
}

func New() *Config {
	return &Config{
		Disabled:       DefaultDisabled,
		ListenAddress:  DefaultListenAddress,
		Endpoint:       DefaultEndpoint,
		SessionDomain:  DefaultSessionDomain,
		DefaultNextURL: DefaultNextURL,
	}
}

func (c *Config) Validate() error {
	if !c.Disabled {
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
	}
	return nil
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.Disabled, "auth-disabled", DefaultDisabled, "Disable the auth api")
	flags.StringVar(&c.ListenAddress, "auth-listen-address", DefaultListenAddress, "The auth api's listen address")
	flags.StringVar(&c.Endpoint, "auth-endpoint", DefaultEndpoint, "The auth api's endpoint")
	flags.BoolVar(&c.TLS, "auth-tls", false, "The auth api's tls")
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
	flags.StringVar(&c.MagicLinkProjectName, "auth-magic-link-project-name", "", "The auth api's magic link project name")
	flags.StringVar(&c.MagicLinkProjectURL, "auth-magic-link-project-url", "", "The auth api's magic link project url")
}

func (c *Config) GenerateOptions(logName string) *auth.Options {
	return &auth.Options{
		LogName:              logName,
		Disabled:             c.Disabled,
		ListenAddress:        c.ListenAddress,
		Endpoint:             c.Endpoint,
		TLS:                  c.TLS,
		SessionDomain:        c.SessionDomain,
		DefaultNextURL:       c.DefaultNextURL,
		GithubClientID:       c.GithubClientID,
		GithubClientSecret:   c.GithubClientSecret,
		GoogleClientID:       c.GoogleClientID,
		GoogleClientSecret:   c.GoogleClientSecret,
		DeviceCodeEnabled:    c.DeviceCode,
		PostmarkAPIToken:     c.PostmarkAPIToken,
		PostmarkTemplateID:   c.PostmarkTemplateID,
		PostmarkTag:          c.PostmarkTag,
		MagicLinkFrom:        c.MagicLinkFrom,
		MagicLinkProjectName: c.MagicLinkProjectName,
		MagicLinkProjectURL:  c.MagicLinkProjectURL,
	}
}
