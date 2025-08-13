//SPDX-License-Identifier: Apache-2.0

package credential

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/loopholelabs/auth/pkg/manager/role"
)

var (
	ErrInvalidSigningKey = errors.New("invalid signing key")
	ErrSigningSession    = errors.New("error signing session")
	ErrParsingSession    = errors.New("error parsing session")
	ErrInvalidSession    = errors.New("invalid session")
	ErrInvalidClaims     = errors.New("invalid claims")
)

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
		s.OrganizationInfo.Name != "" &&
		s.OrganizationInfo.Role.IsValid() &&
		len(s.UserInfo.Identifier) == 36 &&
		s.UserInfo.Email != "" &&
		s.ExpiresAt.After(time.Now())
}

func (s Session) Sign(signingKey ed25519.PrivateKey) (string, error) {
	if !s.IsValid() {
		return "", errors.Join(ErrSigningSession, ErrInvalidSession)
	}

	if signingKey == nil {
		return "", errors.Join(ErrSigningSession, ErrInvalidSigningKey)
	}

	claims := jwt.MapClaims{
		"sub": s.Identifier,                  // Subject is the Session Identifier
		"iss": s.OrganizationInfo.Identifier, // Issuer is the Organization Identifier
		"aud": s.UserInfo.Identifier,         // Audience is the User Identifier
		"exp": s.ExpiresAt.Unix(),            // Expiration time
		"iat": time.Now().Unix(),             // Signing time

		"organization_identifier": s.OrganizationInfo.Identifier,
		"organization_name":       s.OrganizationInfo.Name,
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
	if err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return Session{}, false, errors.Join(ErrParsingSession, err)
	}

	reSign := false
VALIDATE:
	switch {
	case parsedToken.Valid && err == nil:
	case errors.Is(err, jwt.ErrTokenSignatureInvalid) && !reSign:
		parsedToken, err = jwt.Parse(token, keyFunc(previousPublicKey),
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithStrictDecoding(),
		)
		if err != nil {
			return Session{}, reSign, errors.Join(ErrParsingSession, err)
		}
		reSign = true
		goto VALIDATE
	case reSign:
		return Session{}, reSign, errors.Join(ErrParsingSession, jwt.ErrTokenSignatureInvalid)
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, jwt.ErrTokenNotValidYet):
		fallthrough
	default:
		return Session{}, reSign, errors.Join(ErrParsingSession, err)
	}

	if parsedToken.Claims == nil {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	identifier, ok := parseClaims[string]("sub", claims)
	if len(identifier) != 36 || !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	organizationIdentifier, ok := parseClaims[string]("organization_identifier", claims)
	if len(organizationIdentifier) != 36 || !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	iss, ok := parseClaims[string]("iss", claims)
	if iss == "" || !ok || iss != organizationIdentifier {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	organizationName, ok := parseClaims[string]("organization_name", claims)
	if !ok || organizationName == "" {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	organizationIsDefault, ok := parseClaims[bool]("organization_is_default", claims)
	if !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	organizationRoleString, ok := parseClaims[string]("organization_role", claims)
	if organizationRoleString == "" || !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}
	organizationRole := role.Role(organizationRoleString)
	if !organizationRole.IsValid() {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	userIdentifier, ok := parseClaims[string]("user_identifier", claims)
	if len(userIdentifier) != 36 || !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	aud, ok := parseClaims[string]("aud", claims)
	if aud == "" || !ok || aud != userIdentifier {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	userName, ok := parseClaims[string]("user_name", claims)
	if !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	userEmail, ok := parseClaims[string]("user_email", claims)
	if userEmail == "" || !ok {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	generationFloat64, ok := parseClaims[float64]("generation", claims)
	if !ok || generationFloat64 > math.MaxUint32 || generationFloat64 < 0 {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}
	generation := uint32(generationFloat64)

	expirationTime, err := claims.GetExpirationTime()
	if err != nil {
		return Session{}, reSign, errors.Join(ErrParsingSession, err)
	}
	if expirationTime == nil {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidClaims)
	}

	session := Session{
		Identifier: identifier,
		OrganizationInfo: OrganizationInfo{
			Identifier: organizationIdentifier,
			Name:       organizationName,
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
	}

	if !session.IsValid() {
		return Session{}, reSign, errors.Join(ErrParsingSession, ErrInvalidSession)
	}

	return session, reSign, nil
}
