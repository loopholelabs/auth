//SPDX-License-Identifier: Apache-2.0

package manager

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/manager/role"
)

var (
	ErrSigningSession = errors.New("error signing session")
	ErrParsingSession = errors.New("error parsing session")
	ErrInvalidSession = errors.New("invalid session")
	ErrInvalidClaims  = errors.New("invalid claims")
)

type OrganizationInfo struct {
	Identifier string    `json:"identifier"`
	IsDefault  bool      `json:"is_default"`
	Role       role.Role `json:"role"`
}

type UserInfo struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}

type Session struct {
	Identifier       string           `json:"identifier"`
	OrganizationInfo OrganizationInfo `json:"organization_info"`
	UserInfo         UserInfo         `json:"user_info"`
	Generation       uint32           `json:"generation"`
	ExpiresAt        time.Time        `json:"expires_at"`
}

func (s Session) IsValid() bool {
	return len(s.Identifier) == 36 &&
		len(s.OrganizationInfo.Identifier) == 36 &&
		s.OrganizationInfo.Role.IsValid() &&
		len(s.UserInfo.Identifier) == 36 &&
		s.UserInfo.Email != "" &&
		s.ExpiresAt.After(time.Now())
}

func (s Session) Sign(signingKey ed25519.PrivateKey) (string, error) {
	if !s.IsValid() {
		return "", errors.Join(ErrSigningSession, ErrInvalidSession)
	}

	claims := jwt.MapClaims{
		"sub": s.Identifier,                  // Subject is the Session Identifier
		"iss": s.OrganizationInfo.Identifier, // Issuer is the Organization Identifier
		"aud": s.UserInfo.Identifier,         // Audience is the User Identifier
		"exp": s.ExpiresAt.Unix(),            // Expiration time
		"iat": time.Now().Unix(),             // Signing time

		"organization_identifier": s.OrganizationInfo.Identifier,
		"organization_is_default": s.OrganizationInfo.IsDefault,
		"organization_role":       s.OrganizationInfo.Role,

		"user_identifier": s.UserInfo.Identifier,
		"user_name":       s.UserInfo.Name,
		"user_email":      s.UserInfo.Email,

		"generation": s.Generation,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", errors.Join(ErrSigningSession, err)
	}

	return signedToken, nil
}

func ParseSession(token string, publicKey crypto.PublicKey, previousPublicKey crypto.PublicKey) (Session, bool, error) {
	parsedToken, err := jwt.Parse(token, keyFunc(publicKey),
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithStrictDecoding(),
	)
	if err != nil {
		return Session{}, false, errors.Join(ErrParsingSession, err)
	}

	replace := false
VALIDATE:
	switch {
	case parsedToken.Valid:
	case errors.Is(err, jwt.ErrTokenSignatureInvalid) && !replace:
		parsedToken, err = jwt.Parse(token, keyFunc(previousPublicKey),
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithStrictDecoding(),
		)
		if err != nil {
			return Session{}, replace, errors.Join(ErrParsingSession, err)
		}
		replace = true
		goto VALIDATE
	case replace || errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, jwt.ErrTokenNotValidYet):
		fallthrough
	default:
		return Session{}, replace, errors.Join(ErrParsingSession, err)
	}

	if parsedToken.Claims == nil {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	identifier, ok := parseClaims[string]("sub", claims)
	if len(identifier) != 36 || !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	organizationIdentifier, ok := parseClaims[string]("organization_identifier", claims)
	if len(organizationIdentifier) != 36 || !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	iss, ok := parseClaims[string]("iss", claims)
	if iss == "" || !ok || iss != organizationIdentifier {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	organizationIsDefault, ok := parseClaims[bool]("organization_is_default", claims)
	if !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	organizationRole, ok := parseClaims[role.Role]("organization_role", claims)
	if !organizationRole.IsValid() || !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	userIdentifier, ok := parseClaims[string]("user_identifier", claims)
	if len(userIdentifier) != 36 || !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	aud, ok := parseClaims[string]("aud", claims)
	if aud == "" || !ok || aud != userIdentifier {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	userName, ok := parseClaims[string]("user_name", claims)
	if !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	userEmail, ok := parseClaims[string]("user_email", claims)
	if userEmail == "" || !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	generation, ok := parseClaims[uint32]("generation", claims)
	if !ok {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	expirationTime, err := claims.GetExpirationTime()
	if err != nil {
		return Session{}, replace, errors.Join(ErrParsingSession, err)
	}
	if expirationTime == nil {
		return Session{}, replace, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	return Session{
		Identifier: identifier,
		OrganizationInfo: OrganizationInfo{
			Identifier: organizationIdentifier,
			IsDefault:  organizationIsDefault,
			Role:       organizationRole,
		},
		UserInfo: UserInfo{
			Identifier: userIdentifier,
			Name:       userName,
			Email:      userEmail,
		},
		Generation: generation,
		ExpiresAt:  expirationTime.Time,
	}, replace, nil
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
