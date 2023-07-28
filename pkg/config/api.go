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
	"github.com/loopholelabs/auth/internal/api"
	"github.com/spf13/pflag"
)

var (
	ErrAPIListenAddressRequired  = errors.New("api listen address is required")
	ErrAPIEndpointRequired       = errors.New("api endpoint is required")
	ErrAPIDefaultNextURLRequired = errors.New("api default next url is required")

	ErrAPIGithubClientIDRequired     = errors.New("api github client id is required")
	ErrAPIGithubClientSecretRequired = errors.New("api github client secret is required")

	ErrAPIGoogleClientIDRequired     = errors.New("api google client id is required")
	ErrAPIGoogleClientSecretRequired = errors.New("api google client secret is required")

	ErrAPIMagicLinkFromRequired        = errors.New("api magic link from is required")
	ErrAPIMagicLinkProjectNameRequired = errors.New("api magic link project name is required")
	ErrAPIMagicLinkProjectURLRequired  = errors.New("api magic link project url is required")
	ErrAPIPostmarkAPITokenRequired     = errors.New("api postmark api token is required")
	ErrAPIPostmarkTemplateIDRequired   = errors.New("api postmark template id is required")
	ErrAPIPostmarkTagRequired          = errors.New("api postmark tag is required")
)

const (
	APIDefaultDisabled      = true
	APIDefaultListenAddress = "127.0.0.1:8081"
	APIDefaultEndpoint      = "localhost:8081"
	APIDefaultTLS           = false
	APIDefaultNextURL       = "https://loopholelabs.io"
)

type APIConfig struct {
	Disabled             bool   `mapstructure:"disabled"`
	ListenAddress        string `mapstructure:"listen_address"`
	Endpoint             string `mapstructure:"endpoint"`
	TLS                  bool   `mapstructure:"tls"`
	DefaultNextURL       string `mapstructure:"default_next_url"`
	DeviceCodeEnabled    bool   `mapstructure:"device_code_enabled"`
	GithubEnabled        bool   `mapstructure:"github_enabled"`
	GithubClientID       string `mapstructure:"github_client_id"`
	GithubClientSecret   string `mapstructure:"github_client_secret"`
	GoogleEnabled        bool   `mapstructure:"google_enabled"`
	GoogleClientID       string `mapstructure:"github_client_id"`
	GoogleClientSecret   string `mapstructure:"github_client_secret"`
	MagicLinkEnabled     bool   `mapstructure:"magic_link_enabled"`
	MagicLinkFrom        string `mapstructure:"magic_link_from"`
	MagicLinkProjectName string `mapstructure:"magic_link_project_name"`
	MagicLinkProjectURL  string `mapstructure:"magic_link_project_url"`
	PostmarkAPIToken     string `mapstructure:"postmark_api_token"`
	PostmarkTemplateID   int    `mapstructure:"postmark_template_id"`
	PostmarkTag          string `mapstructure:"postmark_tag"`
}

func NewAPI() *APIConfig {
	return &APIConfig{
		Disabled:       APIDefaultDisabled,
		ListenAddress:  APIDefaultListenAddress,
		Endpoint:       APIDefaultEndpoint,
		TLS:            APIDefaultTLS,
		DefaultNextURL: APIDefaultNextURL,
	}
}

func (c *APIConfig) Validate() error {
	if !c.Disabled {
		if c.ListenAddress == "" {
			return ErrAPIListenAddressRequired
		}

		if c.Endpoint == "" {
			return ErrAPIEndpointRequired
		}

		if c.DefaultNextURL == "" {
			return ErrAPIDefaultNextURLRequired
		}

		if c.GithubEnabled {
			if c.GithubClientID == "" {
				return ErrAPIGithubClientIDRequired
			}
			if c.GithubClientSecret == "" {
				return ErrAPIGithubClientSecretRequired
			}
		}

		if c.GoogleEnabled {
			if c.GoogleClientID == "" {
				return ErrAPIGoogleClientIDRequired
			}
			if c.GoogleClientSecret == "" {
				return ErrAPIGoogleClientSecretRequired
			}
		}

		if c.MagicLinkEnabled {
			if c.MagicLinkFrom == "" {
				return ErrAPIMagicLinkFromRequired
			}
			if c.MagicLinkProjectName == "" {
				return ErrAPIMagicLinkProjectNameRequired
			}
			if c.MagicLinkProjectURL == "" {
				return ErrAPIMagicLinkProjectURLRequired
			}
			if c.PostmarkAPIToken == "" {
				return ErrAPIPostmarkAPITokenRequired
			}
			if c.PostmarkTemplateID == 0 {
				return ErrAPIPostmarkTemplateIDRequired
			}
			if c.PostmarkTag == "" {
				return ErrAPIPostmarkTagRequired
			}
		}

	}
	return nil
}

func (c *APIConfig) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.Disabled, "auth-api-disabled", APIDefaultDisabled, "Disable the Auth service's API")
	flags.StringVar(&c.ListenAddress, "auth-api-listen-address", APIDefaultListenAddress, "The Auth service's API listen address")
	flags.StringVar(&c.Endpoint, "auth-api-endpoint", APIDefaultEndpoint, "The Auth service's API endpoint")
	flags.BoolVar(&c.TLS, "auth-api-tls", APIDefaultTLS, "Whether to enable TLS for the Auth service's API")
	flags.StringVar(&c.DefaultNextURL, "auth-api-default-next-url", APIDefaultNextURL, "The auth service's API default next url")
	flags.BoolVar(&c.DeviceCodeEnabled, "auth-api-device-code-enabled", false, "Whether to enable the Auth service's API Device Code Provider")
	flags.BoolVar(&c.GithubEnabled, "auth-api-github-enabled", false, "Whether to enable the Auth service's API Github Provider")
	flags.StringVar(&c.GithubClientID, "auth-api-github-client-id", "", "The Auth service's API Github Client ID")
	flags.StringVar(&c.GithubClientSecret, "auth-api-github-client-secret", "", "The Auth service's API Github Client Secret")
	flags.BoolVar(&c.GoogleEnabled, "auth-api-google-enabled", false, "Whether to enable the Auth service's API Google Provider")
	flags.StringVar(&c.GoogleClientID, "auth-api-google-client-id", "", "The Auth service's API Google Client ID")
	flags.StringVar(&c.GoogleClientSecret, "auth-api-google-client-secret", "", "The Auth service's API Google Client Secret")
	flags.BoolVar(&c.MagicLinkEnabled, "auth-api-magic-link-enabled", false, "Whether to enable the Auth service's API Magic Link Provider")
	flags.StringVar(&c.MagicLinkFrom, "auth-api-magic-link-from", "", "The Auth service's API Magic Link From")
	flags.StringVar(&c.MagicLinkProjectName, "auth-api-magic-link-project-name", "", "The Auth service's API Magic Link Project Name")
	flags.StringVar(&c.MagicLinkProjectURL, "auth-api-magic-link-project-url", "", "The Auth service's API Magic Link Project URL")
	flags.StringVar(&c.PostmarkAPIToken, "auth-api-postmark-api-token", "", "The Auth service's API Postmark API Token")
	flags.IntVar(&c.PostmarkTemplateID, "auth-api-postmark-template-id", 0, "The Auth service's API Postmark Template ID")
	flags.StringVar(&c.PostmarkTag, "auth-api-postmark-tag", "", "The Auth service's API Postmark Tag")
}

func (c *APIConfig) GenerateOptions() *api.Options {
	return &api.Options{
		Disabled:             c.Disabled,
		ListenAddress:        c.ListenAddress,
		Endpoint:             c.Endpoint,
		TLS:                  c.TLS,
		DefaultNextURL:       c.DefaultNextURL,
		DeviceCodeEnabled:    c.DeviceCodeEnabled,
		GithubEnabled:        c.GithubEnabled,
		GithubClientID:       c.GithubClientID,
		GithubClientSecret:   c.GithubClientSecret,
		GoogleEnabled:        c.GoogleEnabled,
		GoogleClientID:       c.GoogleClientID,
		GoogleClientSecret:   c.GoogleClientSecret,
		MagicLinkEnabled:     c.MagicLinkEnabled,
		MagicLinkFrom:        c.MagicLinkFrom,
		MagicLinkProjectName: c.MagicLinkProjectName,
		MagicLinkProjectURL:  c.MagicLinkProjectURL,
		PostmarkAPIToken:     c.PostmarkAPIToken,
		PostmarkTemplateID:   c.PostmarkTemplateID,
		PostmarkTag:          c.PostmarkTag,
	}
}
