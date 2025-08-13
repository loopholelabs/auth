//SPDX-License-Identifier: Apache-2.0

package credential

import (
	"crypto"

	"github.com/golang-jwt/jwt/v5"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/manager/role"
)

type OrganizationInfo struct {
	Identifier string    `json:"identifier"`
	Name       string    `json:"name"`
	IsDefault  bool      `json:"is_default"`
	Role       role.Role `json:"role"`
}

type UserInfo struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}

func keyFunc(publicKey crypto.PublicKey) jwt.Keyfunc {
	return func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	}
}

func parseClaims[T any](key string, claims jwt.MapClaims) (T, bool) {
	iface, ok := claims[key]
	if !ok {
		return utils.GenericZero[T](), false
	}
	claim, ok := iface.(T)
	if !ok {
		return utils.GenericZero[T](), false
	}
	return claim, true
}
