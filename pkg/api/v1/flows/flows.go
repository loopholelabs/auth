//SPDX-License-Identifier: Apache-2.0

package flows

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/device"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/github"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/google"
	"github.com/loopholelabs/auth/pkg/api/v1/flows/magic"
)

type Flows struct {
	logger  types.Logger
	options options.Options
}

func New(options options.Options, logger types.Logger) *Flows {
	return &Flows{
		logger:  logger.SubLogger("FLOWS"),
		options: options,
	}
}

func (f *Flows) Register(prefixes []string, group huma.API) {
	prefixes = append(prefixes, "flows")
	group = huma.NewGroup(group, "/flows")
	device.New(f.options, f.logger).Register(prefixes, group)
	github.New(f.options, f.logger).Register(prefixes, group)
	google.New(f.options, f.logger).Register(prefixes, group)
	magic.New(f.options, f.logger).Register(prefixes, group)
}
