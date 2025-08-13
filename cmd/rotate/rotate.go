//SPDX-License-Identifier: Apache-2.0

package rotate

import (
	"github.com/spf13/cobra"

	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"

	"github.com/loopholelabs/auth/internal/config"
	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
)

func Cmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		c := &cobra.Command{
			Use:   "rotate",
			Short: "Rotate Authentication API Secret",
			RunE: func(c *cobra.Command, _ []string) error {
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

				cfg, err := configuration.New(configuration.Options{
					PollInterval:  ch.Config.PollInterval,
					SessionExpiry: ch.Config.SessionExpiry,
				}, d, ch.Logger)
				if err != nil {
					return err
				}

				defer func() {
					err := cfg.Close()
					if err != nil {
						ch.Printer.Printf("failed to cleanup configuration: %v\n", err)
					}
				}()

				stop := ch.Printer.PrintProgress("Rotating secrets...")
				err = cfg.RotateSigningKey(c.Context())
				stop()
				if err != nil {
					return err
				}
				ch.Printer.Printf("Successfully rotated secrets\n")
				return nil
			},
		}

		if err := ch.Config.API.RequiredFlags(c); err != nil {
			panic(err)
		}
		cmd.AddCommand(c)
	}
}
