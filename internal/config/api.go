//SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	DefaultListenAddress = "127.0.0.1:8080"
	DefaultEndpoint      = "localhost:8080"
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
	ListenAddress string `mapstructure:"listen_address"`
	TLS           bool   `mapstructure:"tls"`
	Endpoint      string `mapstructure:"endpoint"`
	Issuer        string `mapstructure:"issuer"`
	Github        Github `mapstructure:"github"`
	Google        Google `mapstructure:"google"`
	Magic         Magic  `mapstructure:"magic"`
	Device        Device `mapstructure:"device"`
	Mailer        Mailer `mapstructure:"mailer"`
}

func NewAPI() *API {
	return &API{
		ListenAddress: DefaultListenAddress,
		TLS:           false,
		Endpoint:      DefaultEndpoint,
	}
}

func (c *API) RequiredFlags(cmd *cobra.Command) error {
	cmd.Flags().StringVar(&c.ListenAddress, "api-listen-address", DefaultListenAddress, "the address to listen on")
	cmd.Flags().BoolVar(&c.TLS, "api-tls", false, "whether or not to use TLS")
	cmd.Flags().StringVar(&c.Endpoint, "api-endpoint", DefaultEndpoint, "the api endpoint")
	cmd.Flags().StringVar(&c.Issuer, "api-issuer", "authentication-service", "the issuer")
	cmd.Flags().BoolVar(&c.Github.Enabled, "api-github-enabled", false, "enable github provider")
	cmd.Flags().StringVar(&c.Github.ClientID, "api-github-client-id", "", "github provider's client ID")
	cmd.Flags().StringVar(&c.Github.ClientSecret, "api-github-client-secret", "", "github provider's client secret")
	cmd.Flags().BoolVar(&c.Google.Enabled, "api-google-enabled", false, "enable google provider")
	cmd.Flags().StringVar(&c.Google.ClientID, "api-google-client-id", "", "google provider's client ID")
	cmd.Flags().StringVar(&c.Google.ClientSecret, "api-google-client-secret", "", "google provider's client secret")
	cmd.Flags().BoolVar(&c.Magic.Enabled, "api-magic-enabled", false, "enable magic provider")
	cmd.Flags().BoolVar(&c.Device.Enabled, "api-device-enabled", false, "enable device provider")
	cmd.Flags().BoolVar(&c.Mailer.Enabled, "api-mailer-enabled", false, "enable mailer provider")
	cmd.Flags().StringVar(&c.Mailer.SMTPHost, "api-mailer-smtp-host", "", "mailer smtp host")
	cmd.Flags().IntVar(&c.Mailer.SMTPPort, "api-mailer-smtp-port", 0, "mailer provider's smtp port")
	cmd.Flags().StringVar(&c.Mailer.SMTPUsername, "api-mailer-smtp-username", "", "mailer provider's smtp username")
	cmd.Flags().StringVar(&c.Mailer.SMTPPassword, "api-mailer-smtp-password", "", "mailer provider's smtp password")
	cmd.Flags().StringVar(&c.Mailer.FromEmail, "api-mailer-from-email", "", "mailer provider's from email")
	cmd.Flags().StringVar(&c.Mailer.FromName, "api-mailer-from-name", "", "mailer provider's from name")
	cmd.Flags().StringVar(&c.Mailer.MagicLinkTemplatePath, "api-mailer-magic-link-template", "", "mailer provider's magic link template path")

	return nil
}

func (c *API) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen_address is required")
	}

	if c.Endpoint == "" {
		return errors.New("endpoint is required")
	}

	if c.Issuer == "" {
		return errors.New("issuer is required")
	}

	return nil
}
