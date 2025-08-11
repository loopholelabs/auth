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

// RegisterEndpoints registers all flow endpoints with Huma
func RegisterEndpoints(api huma.API, options options.Options, logger types.Logger) {
	flowLogger := logger.SubLogger("FLOWS")

	// Register each flow's endpoints
	device.RegisterEndpoints(api, options, flowLogger)
	google.RegisterEndpoints(api, options, flowLogger)
	github.RegisterEndpoints(api, options, flowLogger)
	magic.RegisterEndpoints(api, options, flowLogger)
}
