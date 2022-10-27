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
	"errors"
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

type Identity struct {
	Kind       tokenKind.Kind
	Claims     interface{}
	Identifier string
	Key        string
}

func ValidateHandler(clientIDs []string, issuer string, keySet keyset.Verifier) fiber.Handler {
	validate := Validate(clientIDs, issuer, keySet)
	return func(ctx *fiber.Ctx) error {
		authorizationHeader := ctx.Request().Header.Peek("Authorization")
		if authorizationHeader == nil || len(authorizationHeader) <= len(BearerPrefix) {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid authorization header")
		}

		i, err := validate(string(authorizationHeader[len(BearerPrefix):]))
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, err.Error())
		}

		ctx.Locals(KindKey, i.Kind)
		ctx.Locals(ClaimsKey, i.Claims)
		ctx.Locals(IdentifierKey, i.Identifier)
		switch i.Kind {
		case tokenKind.APITokenKind:
			ctx.Locals(APIKey, i.Key)
		case tokenKind.ServiceTokenKind:
			ctx.Locals(ServiceKey, i.Key)
		}

		return ctx.Next()
	}
}

func Validate(clientIDs []string, issuer string, keySet keyset.Verifier) func(rawToken string) (*Identity, error) {
	return func(rawToken string) (*Identity, error) {
		partialToken, payload, err := token.PartialPopulate(keySet, rawToken)
		if err != nil {
			return nil, err
		}

		if !partialToken.ValidExpiry() {
			return nil, errors.New("token expired")
		}

		if !partialToken.ValidIssuer(issuer) {
			return nil, errors.New("invalid issuer")
		}

		validAudience := false
		for _, clientID := range clientIDs {
			if partialToken.ValidAudience(clientID) {
				validAudience = true
				break
			}
		}
		if !validAudience {
			return nil, errors.New("invalid audience")
		}

		switch partialToken.Kind {
		case tokenKind.APITokenKind:
			apiClaims := new(token.APIClaims)
			err = json.Unmarshal(payload, apiClaims)
			if err != nil {
				return nil, err
			}
			if !apiClaims.Valid() {
				return nil, errors.New("invalid claims")
			}

			return &Identity{
				Kind:       tokenKind.APITokenKind,
				Claims:     apiClaims,
				Identifier: partialToken.Subject,
				Key:        apiClaims.ID,
			}, nil
		case tokenKind.ServiceTokenKind:
			serviceClaims := new(token.ServiceClaims)
			err = json.Unmarshal(payload, serviceClaims)
			if err != nil {
				return nil, err
			}
			if !serviceClaims.Valid() {
				return nil, errors.New("invalid claims")
			}

			return &Identity{
				Kind:       tokenKind.ServiceTokenKind,
				Claims:     serviceClaims,
				Identifier: partialToken.Subject,
				Key:        serviceClaims.ID,
			}, nil
		case tokenKind.OAuthKind:
			idClaims := new(identity.IDClaims)
			err = json.Unmarshal(payload, idClaims)
			if err != nil {
				return nil, err
			}

			return &Identity{
				Kind:       tokenKind.OAuthKind,
				Claims:     idClaims,
				Identifier: partialToken.Subject,
			}, nil
		case tokenKind.RefreshTokenKind:
			fallthrough
		default:
			return nil, errors.New("invalid token kind")
		}
	}
}
