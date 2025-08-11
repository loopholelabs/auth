//SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"

	"github.com/adrg/xdg"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/loopholelabs/cmdutils/pkg/config"
)

var _ config.Config = (*Config)(nil)

var (
	configFile string
	logFile    string
)

var (
	ErrFailedToUnmarshalConfig = errors.New("failed to unmarshal config")
)

type Config struct {
}

func New() *Config {
	return &Config{}
}

func (c *Config) RootPersistentFlags(_ *pflag.FlagSet) {
	// Add flags here as needed
}

func (c *Config) GlobalRequiredFlags(_ *cobra.Command) error {
	return nil
}

func (c *Config) Parse() error {
	return nil
}

func (c *Config) Validate() error {
	if err := viper.Unmarshal(c); err != nil {
		return errors.Join(ErrFailedToUnmarshalConfig, err)
	}

	return nil
}

func (c *Config) DefaultConfigDir() (string, error) {
	return xdg.ConfigHome, nil
}

func (c *Config) DefaultConfigFile() string {
	return "conduit.yaml"
}

func (c *Config) DefaultLogDir() (string, error) {
	return xdg.StateHome, nil
}

func (c *Config) DefaultLogFile() string {
	return "conduit.log"
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
