//SPDX-License-Identifier: Apache-2.0

package fiber

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humafiber"

	"github.com/loopholelabs/logging/types"
)

func LogIP(identifier string, logger types.Logger) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		logger.Debug().Str("IP", humafiber.Unwrap(ctx).IP()).Msg(identifier)
		next(ctx)
	}
}
