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
	"github.com/loopholelabs/auth/pkg/token/identity"
	"github.com/loopholelabs/auth/pkg/token/tokenKind"
	"github.com/valyala/fasthttp"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	IDPError     = errors.New("error while communicating with Dex IdP")
	NewUserError = errors.New("error while creating new user")
)

func passthrough(handler fasthttp.RequestHandler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		handler(ctx.Context())
		return nil
	}
}

func (s *Server) customClaims(handler fiber.Handler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		err := handler(ctx)
		if err != nil {
			return err
		}
		response := ctx.Response()
		if response.StatusCode() == 200 {
			tokenResponse := new(identity.TokenResponse)
			err = json.Unmarshal(response.Body(), tokenResponse)
			if err != nil {
				s.logger.Errorf("error while unmarshalling tokenResponse from response body: %s", err)
				return IDPError
			}

			if tokenResponse.AccessToken != "" {
				accessToken, err := jwt.ParseSigned(tokenResponse.AccessToken)
				if err != nil {
					s.logger.Errorf("error parsing access tokenResponse from Dex: %s", err)
					return IDPError
				}

				tokenResponse.AccessToken, err = s.parseAndModify(accessToken)
				if err != nil {
					s.logger.Errorf("error modifying access tokenResponse from Dex: %s", err)
					return IDPError
				}
				s.logger.Debugf("modified access tokenResponse: %s", tokenResponse.AccessToken)
			}

			if tokenResponse.IDToken != "" {
				idToken, err := jwt.ParseSigned(tokenResponse.IDToken)
				if err != nil {
					s.logger.Errorf("error parsing id tokenResponse from Dex: %s", err)
					return IDPError
				}

				tokenResponse.IDToken, err = s.parseAndModify(idToken)
				if err != nil {
					s.logger.Errorf("error modifying id tokenResponse from Dex: %s", err)
					return IDPError
				}
				s.logger.Debugf("modified id tokenResponse: %s", tokenResponse.AccessToken)
			}

			payload, err := json.Marshal(tokenResponse)
			if err != nil {
				s.logger.Errorf("error marshalling modified tokenResponse: %s", err)
				return IDPError
			}

			response.SetBody(payload)
		}
		return nil
	}
}

func (s *Server) parseAndModify(jwt *jwt.JSONWebToken) (string, error) {
	claims := new(identity.IDToken)
	err := jwt.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		s.logger.Errorf("error while retrieving claims from JWT: %s", err)
		return "", IDPError
	}

	if len(claims.Email) == 0 {
		s.logger.Errorf("email is empty in tokenResponse")
		return "", IDPError
	}

	exists, err := s.storage.UserExists(claims.Email)
	if err != nil {
		s.logger.Errorf("error while retrieving user from DB: %s", err)
		return "", IDPError
	}

	if !exists {
		if s.options.Registration() {
			err = s.options.NewUser(claims)
			if err != nil {
				s.logger.Errorf("error while creating new user: %s", err)
				return "", NewUserError
			}
			s.logger.Infof("created new user %s", claims.Email)
		} else {

		}
	}

	claims.Subject = claims.Email
	claims.Kind = tokenKind.OAuthKind

	payload, err := json.Marshal(claims)
	if err != nil {
		s.logger.Errorf("error marshalling modified claims: %s", err)
		return "", IDPError
	}

	signedToken, err := s.privateKeys.Sign(jose.RS256, payload)
	if err != nil {
		s.logger.Errorf("error signing payload with modified claims: %s", err)
		return "", IDPError
	}

	return signedToken, nil
}
