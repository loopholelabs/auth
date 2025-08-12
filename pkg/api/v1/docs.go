//go:build docs

//SPDX-License-Identifier: Apache-2.0

package v1

import "github.com/gofiber/fiber/v2"

func (v *V1) docs(ctx *fiber.Ctx) error {
	ctx.Set("content-type", "text/html; charset=utf-8")
	return ctx.SendString(`<!doctype html>
<html>
  <head>
    <title>API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      data-url="/v1/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`)
}
