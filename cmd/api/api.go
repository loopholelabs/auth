//SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"

	"github.com/loopholelabs/auth/internal/config"
	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/pkg/api"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/manager"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
)

func Cmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		c := &cobra.Command{
			Use:   "api",
			Short: "Run Authentication API",
			PreRunE: func(_ *cobra.Command, _ []string) error {
				if err := ch.Config.API.Validate(); err != nil {
					return errors.Join(config.ErrFailedToValidateConfig, err)
				}
				return nil
			},
			RunE: func(c *cobra.Command, _ []string) error {
				ch.Printer.Printf("Running Authentication API... %s\n", ch.Config.API.ListenAddress)

				d, err := db.New(ch.Config.Database, ch.Logger)
				if err != nil {
					return err
				}

				defer func() {
					err := d.Close()
					if err != nil {
						ch.Printer.Printf("failed to cleanup database: %v\n", err)
					}
				}()

				m, err := manager.New(manager.Options{
					Github: manager.GithubOptions{
						Enabled:      ch.Config.API.Github.Enabled,
						ClientID:     ch.Config.API.Github.ClientID,
						ClientSecret: ch.Config.API.Github.ClientSecret,
					},
					Google: manager.GoogleOptions{
						Enabled:      ch.Config.API.Google.Enabled,
						ClientID:     ch.Config.API.Google.ClientID,
						ClientSecret: ch.Config.API.Google.ClientSecret,
					},
					Magic: manager.MagicOptions{
						Enabled: ch.Config.API.Magic.Enabled,
					},
					Device: manager.DeviceOptions{
						Enabled: ch.Config.API.Device.Enabled,
					},
					Mailer: manager.MailerOptions{
						Enabled:               ch.Config.API.Mailer.Enabled,
						SMTPHost:              ch.Config.API.Mailer.SMTPHost,
						SMTPPort:              ch.Config.API.Mailer.SMTPPort,
						SMTPUsername:          ch.Config.API.Mailer.SMTPUsername,
						SMTPPassword:          ch.Config.API.Mailer.SMTPPassword,
						FromEmail:             ch.Config.API.Mailer.FromEmail,
						FromName:              ch.Config.API.Mailer.FromName,
						AppName:               ch.Config.API.Issuer,
						MagicLinkTemplatePath: ch.Config.API.Mailer.MagicLinkTemplatePath,
					},
					Configuration: configuration.Options{
						PollInterval:  ch.Config.PollInterval,
						SessionExpiry: ch.Config.SessionExpiry,
					},
					API: manager.APIOptions{
						TLS:      ch.Config.API.TLS,
						Endpoint: ch.Config.API.Endpoint,
					},
				}, d, ch.Logger)
				if err != nil {
					return err
				}

				defer func() {
					err := m.Close()
					if err != nil {
						ch.Printer.Printf("failed to cleanup manager: %v\n", err)
					}
				}()

				a, err := api.New(options.Options{
					Endpoint: ch.Config.API.Endpoint,
					TLS:      ch.Config.API.TLS,
					Manager:  m,
				}, ch.Logger)
				if err != nil {
					return err
				}

				defer func() {
					err := a.Close()
					if err != nil {
						ch.Printer.Printf("failed to cleanup API: %v\n", err)
					}
				}()

				errCh := make(chan error, 1)
				done := make(chan os.Signal, 1)
				signal.Notify(done, os.Interrupt, syscall.SIGTERM)

				go func() {
					err := a.Start(ch.Config.API.ListenAddress)
					if err != nil {
						ch.Printer.Printf("failed to start API server: %v\n", err)
						errCh <- err
					}
				}()

				select {
				case err = <-errCh:
					ch.Logger.Error().Err(err).Msg("API server terminated")
				case <-done:
					ch.Logger.Info().Msg("exiting gracefully")
				case <-c.Context().Done():
					ch.Logger.Info().Msg("exiting gracefully")
				}

				return nil
			},
		}

		if err := ch.Config.API.RequiredFlags(c); err != nil {
			panic(err)
		}

		cmd.AddCommand(c)
	}
}
