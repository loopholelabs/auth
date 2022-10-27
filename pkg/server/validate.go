/*
	Copyright 2022 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package server

import (
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/pkg/keyset"
	"github.com/loopholelabs/auth/pkg/token"
	"github.com/loopholelabs/auth/pkg/token/identity"
	"github.com/loopholelabs/auth/pkg/token/tokenKind"
)

var (
	BearerPrefix = []byte("Bearer ")
)

const (
	KindKey       = "kind"
	ClaimsKey     = "claims"
	IdentifierKey = "identifier"
	APIKey        = "api"
	ServiceKey    = "service"
)

func Validate(clientID string, issuer string, keySet *keyset.Public) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authorizationHeader := ctx.Request().Header.Peek("Authorization")
		if authorizationHeader == nil || len(authorizationHeader) <= len(BearerPrefix) {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid authorization header")
		}

		partialToken, payload, err := token.PartialPopulate(keySet, string(authorizationHeader[len(BearerPrefix):]))
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, err.Error())
		}

		if !partialToken.ValidExpiry() {
			return fiber.NewError(fiber.StatusUnauthorized, "token expired")
		}

		if !partialToken.ValidIssuer(issuer) {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid issuer")
		}

		switch partialToken.Kind {
		case tokenKind.APITokenKind:
			if !partialToken.ValidAudience(identity.MachineAudience) {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid audience")
			}
			apiClaims := new(token.APIClaims)
			err = json.Unmarshal(payload, apiClaims)
			if err != nil {
				return fiber.NewError(fiber.StatusUnauthorized, err.Error())
			}
			if !apiClaims.Valid() {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid claims")
			}

			ctx.Locals(KindKey, tokenKind.APITokenKind)
			ctx.Locals(ClaimsKey, apiClaims)
			ctx.Locals(IdentifierKey, partialToken.Subject)
			ctx.Locals(APIKey, apiClaims.ID)
		case tokenKind.ServiceTokenKind:
			if !partialToken.ValidAudience(identity.MachineAudience) {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid audience")
			}
			serviceClaims := new(token.ServiceClaims)
			err = json.Unmarshal(payload, serviceClaims)
			if err != nil {
				return fiber.NewError(fiber.StatusUnauthorized, err.Error())
			}
			if !serviceClaims.Valid() {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid claims")
			}

			ctx.Locals(KindKey, tokenKind.ServiceTokenKind)
			ctx.Locals(ClaimsKey, serviceClaims)
			ctx.Locals(IdentifierKey, partialToken.Subject)
			ctx.Locals(ServiceKey, serviceClaims.ID)
		case tokenKind.OAuthKind:
			if !partialToken.ValidAudience(clientID) {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid audience")
			}
			idClaims := new(identity.IDClaims)
			err = json.Unmarshal(payload, idClaims)
			if err != nil {
				return fiber.NewError(fiber.StatusUnauthorized, err.Error())
			}

			ctx.Locals(KindKey, tokenKind.OAuthKind)
			ctx.Locals(ClaimsKey, idClaims)
			ctx.Locals(IdentifierKey, partialToken.Subject)
		case tokenKind.RefreshTokenKind:
			fallthrough
		default:
			return fiber.NewError(fiber.StatusUnauthorized, "invalid token kind")
		}
		return ctx.Next()
	}
}
