//SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
)

type Rotate struct {
	Database      string        `mapstructure:"database"`
	PollInterval  time.Duration `mapstructure:"poll_interval"`
	SessionExpiry time.Duration `mapstructure:"session_expiry"`
}

func NewRotate() *Rotate {
	return &Rotate{
		PollInterval:  DefaultPollInterval,
		SessionExpiry: DefaultSessionExpiry,
	}
}

func (c *Rotate) RequiredFlags(cmd *cobra.Command) error {
	cmd.Flags().StringVar(&c.Database, "database", "", "the database to connect to")
	cmd.Flags().DurationVar(&c.PollInterval, "poll_interval", DefaultPollInterval, "the default polling interval")
	cmd.Flags().DurationVar(&c.SessionExpiry, "session_expiry", DefaultSessionExpiry, "the session expiration time")

	return nil
}

func (c *Rotate) Validate() error {
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
