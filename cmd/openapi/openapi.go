//SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"

	"github.com/loopholelabs/auth/internal/config"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1"
)

func Cmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		var output string
		c := &cobra.Command{
			Use:   "openapi",
			Short: "Generate OpenAPI Specification",
			PreRunE: func(cmd *cobra.Command, args []string) error {
				if output == "" {
					return errors.New("no output file specified")
				}
				return nil
			},
			RunE: func(c *cobra.Command, _ []string) error {
				ch.Printer.Printf("Generating OpenAPI Specification...\n")
				v1API := v1.New(options.Options{
					Endpoint: ch.Config.API.Endpoint,
					TLS:      ch.Config.API.TLS,
				}, ch.Logger)
				v1OpenAPI := v1API.OpenAPI()
				v1OpenAPIBytes, err := v1OpenAPI.YAML()
				if err != nil {
					return err
				}

				err = os.WriteFile(output, v1OpenAPIBytes, 0644)
				if err != nil {
					return err
				}

				return nil
			},
		}
		c.Flags().StringVar(&output, "output", "openapi.yaml", "output file")

		cmd.AddCommand(c)
	}
}
