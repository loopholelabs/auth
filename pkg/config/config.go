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
	ErrSessionDomainRequired = errors.New("session domain is required")
)

const (
	DefaultDisabled      = false
	DefaultSessionDomain = "localhost"
	DefaultTLS           = true
)

type Config struct {
	Disabled      bool       `yaml:"disabled"`
	SessionDomain string     `yaml:"session_domain"`
	TLS           bool       `yaml:"tls"`
	API           *APIConfig `yaml:"api"`
}

func New() *Config {
	return &Config{
		Disabled:      DefaultDisabled,
		SessionDomain: DefaultSessionDomain,
		TLS:           DefaultTLS,
		API:           NewAPI(),
	}
}

func (c *Config) Validate() error {
	if !c.Disabled {
		if c.SessionDomain == "" {
			return ErrSessionDomainRequired
		}

		return c.API.Validate()
	}
	return nil
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.Disabled, "auth-disabled", DefaultDisabled, "Disable the auth service")
	flags.StringVar(&c.SessionDomain, "auth-session-domain", DefaultSessionDomain, "The auth service's session domain")
	flags.BoolVar(&c.TLS, "auth-tls", DefaultTLS, "Enable TLS for the auth service")
	c.API.RootPersistentFlags(flags)
}

func (c *Config) GenerateOptions(logName string) *auth.Options {
	return &auth.Options{
		LogName:       logName,
		Disabled:      c.Disabled,
		SessionDomain: c.SessionDomain,
		TLS:           c.TLS,
		API:           c.API.GenerateOptions(),
	}
}
