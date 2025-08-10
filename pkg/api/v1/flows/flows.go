//SPDX-License-Identifier: Apache-2.0

package flows

import (
	"github.com/gofiber/fiber/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/device"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/github"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/google"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/magic"
)

type Flows struct {
	logger types.Logger
	app    *fiber.App

	options options.Options
}

func New(options options.Options, logger types.Logger) *Flows {
	a := &Flows{
		logger:  logger.SubLogger("FLOWS"),
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	a.app.Mount("/device", device.New(options, a.logger).App())
	a.app.Mount("/google", google.New(options, a.logger).App())
	a.app.Mount("/github", github.New(options, a.logger).App())
	a.app.Mount("/magic", magic.New(options, a.logger).App())

	return a
}

func (a *Flows) App() *fiber.App {
	return a.app
}
