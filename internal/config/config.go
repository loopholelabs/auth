//SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"time"

	"github.com/adrg/xdg"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/loopholelabs/cmdutils/pkg/config"
)

var _ config.Config = (*Config)(nil)

const (
	DefaultPollInterval  = time.Second * 5
	DefaultSessionExpiry = time.Hour * 24
)

var (
	configFile string
	logFile    string
)

var (
	ErrFailedToUnmarshalConfig = errors.New("failed to unmarshal config")
	ErrFailedToValidateConfig  = errors.New("failed to validate config")
)

type Config struct {
	Database      string        `mapstructure:"database"`
	PollInterval  time.Duration `mapstructure:"poll_interval"`
	SessionExpiry time.Duration `mapstructure:"session_expiry"`
	API           *API          `mapstructure:"api"`
}

func New() *Config {
	return &Config{
		PollInterval:  DefaultPollInterval,
		SessionExpiry: DefaultSessionExpiry,
		API:           NewAPI(),
	}
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.StringVar(&c.Database, "database", "", "the database to connect to")
	flags.DurationVar(&c.PollInterval, "poll_interval", DefaultPollInterval, "the default polling interval")
	flags.DurationVar(&c.SessionExpiry, "session_expiry", DefaultSessionExpiry, "the session expiration time")
}

func (c *Config) GlobalRequiredFlags(_ *cobra.Command) error {
	return nil
}

func (c *Config) Validate() error {
	if err := viper.Unmarshal(c); err != nil {
		return errors.Join(ErrFailedToUnmarshalConfig, err)
	}

	if c.Database == "" {
		return errors.New("database is required")
	}

	if c.PollInterval == 0 {
		return errors.New("poll_interval is required")
	}

	if c.SessionExpiry == 0 {
		return errors.New("session_expiry is required")
	}

	return nil
}

func (c *Config) DefaultConfigDir() (string, error) {
	return xdg.ConfigHome, nil
}

func (c *Config) DefaultConfigFile() string {
	return "auth.yaml"
}

func (c *Config) DefaultLogDir() (string, error) {
	return xdg.StateHome, nil
}

func (c *Config) DefaultLogFile() string {
	return "auth.log"
}

func (c *Config) SetConfigFile(file string) {
	configFile = file
}

func (c *Config) GetConfigFile() string {
	return configFile
}

func (c *Config) SetLogFile(file string) {
	logFile = file
}

func (c *Config) GetLogFile() string {
	return logFile
}
