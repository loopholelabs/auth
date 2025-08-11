//SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
)

const (
	DefaultListenAddress = "127.0.0.1:8080"
	DefaultPollInterval  = time.Second * 30
	DefaultSessionExpiry = time.Hour * 24
)

type Github struct {
	Enabled      bool   `mapstructure:"enabled"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

type Google struct {
	Enabled      bool   `mapstructure:"enabled"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

type Magic struct {
	Enabled bool `mapstructure:"enabled"`
}

type Device struct {
	Enabled bool `mapstructure:"enabled"`
}

type Mailer struct {
	Enabled               bool   `mapstructure:"enabled"`
	SMTPHost              string `mapstructure:"smtp_host"`
	SMTPPort              int    `mapstructure:"smtp_port"`
	SMTPUsername          string `mapstructure:"smtp_username"`
	SMTPPassword          string `mapstructure:"smtp_password"`
	FromEmail             string `mapstructure:"from_email"`
	FromName              string `mapstructure:"from_name"`
	MagicLinkTemplatePath string `mapstructure:"magic_link_template_path"`
}

type API struct {
	ListenAddress string        `mapstructure:"listen_address"`
	Database      string        `mapstructure:"database"`
	TLS           bool          `mapstructure:"tls"`
	Endpoint      string        `mapstructure:"endpoint"`
	Issuer        string        `mapstructure:"issuer"`
	PollInterval  time.Duration `mapstructure:"poll_interval"`
	SessionExpiry time.Duration `mapstructure:"session_expiry"`
	Github        Github        `mapstructure:"github"`
	Google        Google        `mapstructure:"google"`
	Magic         Magic         `mapstructure:"magic"`
	Device        Device        `mapstructure:"device"`
	Mailer        Mailer        `mapstructure:"mailer"`
}

func NewAPI() *API {
	return &API{
		ListenAddress: DefaultListenAddress,
		TLS:           false,
		Endpoint:      DefaultListenAddress,
		PollInterval:  DefaultPollInterval,
		SessionExpiry: DefaultSessionExpiry,
	}
}

func (c *API) RequiredFlags(cmd *cobra.Command) error {
	cmd.Flags().StringVar(&c.ListenAddress, "listen_address", DefaultListenAddress, "the address to listen on")
	cmd.Flags().StringVar(&c.Database, "database", "", "the database to connect to")
	cmd.Flags().BoolVar(&c.TLS, "tls", false, "whether or not to use TLS")
	cmd.Flags().StringVar(&c.Endpoint, "endpoint", DefaultListenAddress, "the api endpoint")
	cmd.Flags().StringVar(&c.Issuer, "issuer", "authentication-service", "the issuer")
	cmd.Flags().DurationVar(&c.PollInterval, "poll_interval", DefaultPollInterval, "the default polling interval")
	cmd.Flags().DurationVar(&c.SessionExpiry, "session_expiry", DefaultSessionExpiry, "the session expiration time")

	return nil
}

func (c *API) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen_address is required")
	}

	if c.Database == "" {
		return errors.New("database is required")
	}

	if c.Endpoint == "" {
		return errors.New("endpoint is required")
	}

	if c.Issuer == "" {
		return errors.New("issuer is required")
	}

	if c.PollInterval == 0 {
		return errors.New("poll_interval is required")
	}

	if c.SessionExpiry == 0 {
		return errors.New("session_expiry is required")
	}

	return nil
}
