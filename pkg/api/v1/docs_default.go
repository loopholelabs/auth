//go:build !docs

//SPDX-License-Identifier: Apache-2.0

package v1

import "github.com/gofiber/fiber/v2"

func (v *V1) docs(ctx *fiber.Ctx) error {
	return ctx.SendStatus(fiber.StatusNotFound)
}
