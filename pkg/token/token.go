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
	"errors"
	"fmt"
	"github.com/loopholelabs/auth/pkg/keyset"
	"github.com/loopholelabs/auth/pkg/token/tokenKind"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/square/go-jose.v2"
	"strings"
	"time"
)

var (
	InvalidTokenKindError = errors.New("invalid token kind")
	MalformedTokenError   = errors.New("encoded token is malformed")
)

var (
	Separator = "."
)

func Hash(secret string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
}

func Encode(identifier string, secret string) string {
	return fmt.Sprintf("%s%s%s", identifier, Separator, secret)
}

func Decode(encoded string) (string, string, error) {
	separated := strings.Split(encoded, Separator)
	if len(separated) != 2 {
		return "", "", MalformedTokenError
	}

	return separated[0], separated[1], nil
}

func Verify(secret string, hash []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(secret)) == nil
}

type BaseClaims struct {
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub"`
	Audience Audience       `json:"aud"`
	Expiry   Time           `json:"exp"`
	IssuedAt Time           `json:"iat"`
	Kind     tokenKind.Kind `json:"kind"`
}

type OAuthTime struct {
	Expiry   int64 `json:"exp"`
	IssuedAt int64 `json:"iat"`
}

type PartialToken BaseClaims

func PartialPopulate(keySet *keyset.Public, token string) (*PartialToken, []byte, error) {
	sig, err := jose.ParseSigned(token)
	if err != nil {
		return nil, nil, err
	}

	payload, err := keySet.Verify(sig)
	if err != nil {
		return nil, nil, err
	}

	partialToken := new(PartialToken)
	err = json.Unmarshal(payload, partialToken)
	if err != nil {
		return nil, nil, err
	}

	switch partialToken.Kind {
	case tokenKind.OAuthKind:
		oauthTime := new(OAuthTime)
		err = json.Unmarshal(payload, oauthTime)
		if err != nil {
			return nil, nil, err
		}
		partialToken.Expiry = Time(time.Unix(oauthTime.Expiry, 0))
		partialToken.IssuedAt = Time(time.Unix(oauthTime.IssuedAt, 0))
		return partialToken, payload, nil
	case tokenKind.APITokenKind, tokenKind.ServiceTokenKind:
		return partialToken, payload, nil
	}

	return nil, nil, InvalidTokenKindError
}

func UnsafePartialPopulate(token string) (*PartialToken, []byte, error) {
	sig, err := jose.ParseSigned(token)
	if err != nil {
		return nil, nil, err
	}

	payload := sig.UnsafePayloadWithoutVerification()
	partialToken := new(PartialToken)
	return partialToken, payload, json.Unmarshal(payload, partialToken)
}

func (p *PartialToken) ValidExpiry() bool {
	return time.Time(p.Expiry).After(time.Now())
}

func (p *PartialToken) ValidKind(kind tokenKind.Kind) bool {
	return p.Kind == kind
}

func (p *PartialToken) ValidIssuer(issuer string) bool {
	return p.Issuer == issuer
}

func (p *PartialToken) ValidAudience(audience string) bool {
	for _, a := range p.Audience {
		if a == audience {
			return true
		}
	}
	return false
}

func (p *PartialToken) ValidSubject(subject string) bool {
	return p.Subject == subject
}
