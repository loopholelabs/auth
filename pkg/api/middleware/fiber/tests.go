//go:build test

//SPDX-License-Identifier: Apache-2.0

package fiber

import (
	"github.com/danielgtaylor/huma/v2"

	"github.com/loopholelabs/logging/types"
)

func LogIP(_ string, _ types.Logger) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		next(ctx)
	}
}
