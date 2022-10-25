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

package token

import (
	"encoding/json"
	"github.com/loopholelabs/auth/pkg/keyset"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/auth/pkg/token/tokenKind"
	"gopkg.in/square/go-jose.v2"
	"time"
)

type APIClaims struct {
	ID string `json:"id"`
}

func (c *APIClaims) Valid() bool {
	return len(c.ID) == 36
}

type APIToken struct {
	BaseClaims
	APIClaims
}

func NewAPIToken(issuer string, apiKey *storage.APIKey, audience Audience) *APIToken {
	return &APIToken{
		BaseClaims: BaseClaims{
			Issuer:   issuer,
			Subject:  apiKey.User,
			Audience: audience,
			Expiry:   Time(time.Now().Add(time.Minute * 5)),
			IssuedAt: Time(time.Now()),
			Kind:     tokenKind.APITokenKind,
		},
		APIClaims: APIClaims{
			ID: apiKey.ID,
		},
	}
}

func (t *APIToken) Payload() ([]byte, error) {
	return json.Marshal(t)
}

func (t *APIToken) Sign(keySet *keyset.Private, alg jose.SignatureAlgorithm) (string, error) {
	payload, err := t.Payload()
	if err != nil {
		return "", err
	}

	return keySet.Sign(alg, payload)
}

func (t *APIToken) Populate(jws string, keySet *keyset.Public) error {
	sig, err := jose.ParseSigned(jws)
	if err != nil {
		return err
	}

	payload, err := keySet.Verify(sig)
	if err != nil {
		return err
	}

	err = json.Unmarshal(payload, t)
	if err != nil {
		return err
	}

	if t.Kind != tokenKind.APITokenKind {
		return InvalidTokenKindError
	}

	return nil
}
