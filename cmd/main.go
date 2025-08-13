//SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/version"

	"github.com/loopholelabs/auth/cmd/api"
	"github.com/loopholelabs/auth/cmd/rotate"
	"github.com/loopholelabs/auth/internal/config"
	authVersion "github.com/loopholelabs/auth/version"
)

var cmd = command.New(
	"auth",
	"Authentication",
	"Authentication Service",
	true,
	version.New[*config.Config](authVersion.GitCommit, authVersion.GoVersion, authVersion.Platform, authVersion.Version, authVersion.BuildDate),
	config.New,
	[]command.SetupCommand[*config.Config]{
		api.Cmd(),
		rotate.Cmd(),
	},
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return cmd.Execute(ctx, command.Interactive)
}
