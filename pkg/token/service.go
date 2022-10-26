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
	"github.com/google/uuid"
	"github.com/loopholelabs/auth/pkg/keyset"
	"github.com/loopholelabs/auth/pkg/token/tokenKind"
	"github.com/loopholelabs/auth/pkg/utils"
	"gopkg.in/square/go-jose.v2"
	"time"
)

// ServiceKey should be of the form "S.<ID>.<SECRET>" - when the secret is stored in the database, it should be hashed
// to a byte slice.
//
// The 'S' prefix is used to differentiate between API keys and Service Keys.
type ServiceKey struct {
	Created  int64
	ID       string
	Secret   []byte
	User     string
	Resource string
	NumUsed  int64
	MaxUses  int64
	Expires  int64
}

func NewServiceKey(user string, resource string, maxUses int64, expires int64) (*ServiceKey, string, error) {
	id := uuid.New().String()
	secret := uuid.New().String()
	encoded := Encode("S", id, secret)
	hashedSecret, err := Hash(secret)
	if err != nil {
		return nil, "", err
	}
	return &ServiceKey{
		Created:  utils.TimeToInt64(time.Now()),
		ID:       id,
		Secret:   hashedSecret,
		User:     user,
		Resource: resource,
		MaxUses:  maxUses,
		Expires:  expires,
	}, encoded, nil
}

type ServiceClaims struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
}

func (c *ServiceClaims) Valid() bool {
	return len(c.ID) == 36
}

type ServiceToken struct {
	BaseClaims
	ServiceClaims
}

func NewServiceToken(issuer string, serviceKey *ServiceKey, audience Audience) *ServiceToken {
	return &ServiceToken{
		BaseClaims: BaseClaims{
			Issuer:   issuer,
			Subject:  serviceKey.User,
			Audience: audience,
			Expiry:   Time(time.Now().Add(time.Minute * 5)),
			IssuedAt: Time(time.Now()),
			Kind:     tokenKind.ServiceTokenKind,
		},
		ServiceClaims: ServiceClaims{
			ID:       serviceKey.ID,
			Resource: serviceKey.Resource,
		},
	}
}

func (t *ServiceToken) Payload() ([]byte, error) {
	return json.Marshal(t)
}

func (t *ServiceToken) Sign(keySet *keyset.Private, alg jose.SignatureAlgorithm) (string, error) {
	payload, err := t.Payload()
	if err != nil {
		return "", err
	}

	return keySet.Sign(alg, payload)
}

func (t *ServiceToken) Populate(jws string, keySet *keyset.Public) error {
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

	if t.Kind != tokenKind.ServiceTokenKind {
		return InvalidTokenKindError
	}

	return nil
}
