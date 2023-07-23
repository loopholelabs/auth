/*
	Copyright 2023 Loophole Labs

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

package helpers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/controller"
	"github.com/loopholelabs/auth/pkg/apikey"
	"github.com/loopholelabs/auth/pkg/key"
	"github.com/loopholelabs/auth/pkg/kind"
	"github.com/loopholelabs/auth/pkg/servicesession"
	"github.com/loopholelabs/auth/pkg/session"
)

func Delimiter() string {
	return controller.KeyDelimiterString
}

func AuthAvailable(ctx *fiber.Ctx) bool {
	cookie := ctx.Cookies(controller.CookieKeyString)
	if cookie != "" {
		return true
	}

	authHeader := ctx.Request().Header.PeekBytes(controller.AuthorizationHeader)
	if len(authHeader) > len(controller.BearerHeader) {
		return true
	}

	return false
}

func GetAuthFromContext(ctx *fiber.Ctx) (kind.Kind, string, string, error) {
	authKind, ok := ctx.Locals(key.KindContext).(kind.Kind)
	if !ok || authKind == "" {
		return "", "", "", controller.ErrInvalidContext
	}

	userID, ok := ctx.Locals(key.UserContext).(string)
	if !ok || userID == "" {
		return "", "", "", controller.ErrInvalidContext
	}

	orgID, ok := ctx.Locals(key.OrganizationContext).(string)
	if !ok {
		return "", "", "", controller.ErrInvalidContext
	}
	return authKind, userID, orgID, nil
}

func GetSessionFromContext(ctx *fiber.Ctx) (*session.Session, error) {
	sess, ok := ctx.Locals(key.SessionContext).(*session.Session)
	if !ok || sess == nil {
		return nil, controller.ErrInvalidContext
	}

	return sess, nil
}

func GetAPIKeyFromContext(ctx *fiber.Ctx) (*apikey.APIKey, error) {
	k, ok := ctx.Locals(key.APIKeyContext).(*apikey.APIKey)
	if !ok || k == nil {
		return nil, controller.ErrInvalidContext
	}

	return k, nil
}

func GetServiceSessionFromContext(ctx *fiber.Ctx) (*servicesession.ServiceSession, error) {
	sess, ok := ctx.Locals(key.ServiceSessionContext).(*servicesession.ServiceSession)
	if !ok || sess == nil {
		return nil, controller.ErrInvalidContext
	}

	return sess, nil
}
