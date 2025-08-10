//SPDX-License-Identifier: Apache-2.0

package manager

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/loopholelabs/auth/pkg/manager/role"
)

// Helper function to create a valid session for testing
func createValidSession(_ *testing.T) Session {
	return Session{
		Identifier: uuid.New().String(),
		OrganizationInfo: OrganizationInfo{
			Identifier: uuid.New().String(),
			IsDefault:  true,
			Role:       role.AdminRole,
		},
		UserInfo: UserInfo{
			Identifier: uuid.New().String(),
			Name:       "Test User",
			Email:      "test@example.com",
		},
		Generation: 1,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
}

func TestSession_IsValid(t *testing.T) {
	t.Run("ValidSession", func(t *testing.T) {
		session := createValidSession(t)
		assert.True(t, session.IsValid())
	})

	t.Run("InvalidSessionIdentifier", func(t *testing.T) {
		session := createValidSession(t)

		// Test empty identifier
		session.Identifier = ""
		assert.False(t, session.IsValid())

		// Test short identifier
		session.Identifier = "too-short"
		assert.False(t, session.IsValid())

		// Test long identifier
		session.Identifier = strings.Repeat("a", 37)
		assert.False(t, session.IsValid())
	})

	t.Run("InvalidOrganizationIdentifier", func(t *testing.T) {
		session := createValidSession(t)

		// Test empty identifier
		session.OrganizationInfo.Identifier = ""
		assert.False(t, session.IsValid())

		// Test wrong length
		session.OrganizationInfo.Identifier = "not-a-uuid"
		assert.False(t, session.IsValid())
	})

	t.Run("InvalidRole", func(t *testing.T) {
		session := createValidSession(t)

		// Test invalid role
		session.OrganizationInfo.Role = role.Role("invalid-role")
		assert.False(t, session.IsValid())

		// Test empty role
		session.OrganizationInfo.Role = ""
		assert.False(t, session.IsValid())
	})

	t.Run("InvalidUserIdentifier", func(t *testing.T) {
		session := createValidSession(t)

		// Test empty identifier
		session.UserInfo.Identifier = ""
		assert.False(t, session.IsValid())

		// Test wrong length
		session.UserInfo.Identifier = "not-a-uuid"
		assert.False(t, session.IsValid())
	})

	t.Run("InvalidEmail", func(t *testing.T) {
		session := createValidSession(t)

		// Test empty email
		session.UserInfo.Email = ""
		assert.False(t, session.IsValid())
	})

	t.Run("ExpiredSession", func(t *testing.T) {
		session := createValidSession(t)

		// Test past expiration
		session.ExpiresAt = time.Now().Add(-time.Hour)
		assert.False(t, session.IsValid())

		// Test exactly now (should be invalid)
		session.ExpiresAt = time.Now()
		assert.False(t, session.IsValid())

		// Test 1 second in future (should be valid)
		session.ExpiresAt = time.Now().Add(time.Second)
		assert.True(t, session.IsValid())
	})

	t.Run("ValidRoles", func(t *testing.T) {
		validRoles := []role.Role{
			role.OwnerRole,
			role.AdminRole,
			role.MemberRole,
			role.ViewerRole,
		}

		for _, r := range validRoles {
			session := createValidSession(t)
			session.OrganizationInfo.Role = r
			assert.True(t, session.IsValid(), "Role %s should be valid", r)
		}
	})

	t.Run("EdgeCaseGeneration", func(t *testing.T) {
		session := createValidSession(t)

		// Generation 0 should still be valid
		session.Generation = 0
		assert.True(t, session.IsValid())

		// Very high generation should still be valid
		session.Generation = ^uint32(0) // Max uint32
		assert.True(t, session.IsValid())
	})

	t.Run("EmptyUserName", func(t *testing.T) {
		session := createValidSession(t)

		// Empty user name should still be valid (only email is required)
		session.UserInfo.Name = ""
		assert.True(t, session.IsValid())
	})
}

func TestSession_Sign(t *testing.T) {
	// Generate test keys
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := privateKey.Public()

	t.Run("SignValidSession", func(t *testing.T) {
		session := createValidSession(t)

		token, err := session.Sign(privateKey)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Verify the token can be parsed back
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		// Verify claims
		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok)
		assert.Equal(t, session.Identifier, claims["sub"])
		assert.Equal(t, session.OrganizationInfo.Identifier, claims["iss"])
		assert.Equal(t, session.UserInfo.Identifier, claims["aud"])
		assert.Equal(t, session.UserInfo.Email, claims["user_email"])
		assert.Equal(t, session.UserInfo.Name, claims["user_name"])
		assert.Equal(t, session.OrganizationInfo.IsDefault, claims["organization_is_default"])
		assert.Equal(t, string(session.OrganizationInfo.Role), claims["organization_role"])
		assert.Equal(t, float64(session.Generation), claims["generation"])
	})

	t.Run("SignInvalidSession", func(t *testing.T) {
		session := createValidSession(t)

		// Make session invalid
		session.ExpiresAt = time.Now().Add(-time.Hour)

		token, err := session.Sign(privateKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSigningSession)
		assert.ErrorIs(t, err, ErrInvalidSession)
		assert.Empty(t, token)
	})

	t.Run("SignWithNilKey", func(t *testing.T) {
		session := createValidSession(t)

		token, err := session.Sign(nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSigningSession)
		assert.ErrorIs(t, err, ErrInvalidSigningKey)
		assert.Empty(t, token)
	})

	t.Run("SignWithEmptyKey", func(t *testing.T) {
		session := createValidSession(t)

		var emptyKey ed25519.PrivateKey
		token, err := session.Sign(emptyKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSigningSession)
		assert.ErrorIs(t, err, ErrInvalidSigningKey)
		assert.Empty(t, token)
	})

	t.Run("TokenExpirationTime", func(t *testing.T) {
		session := createValidSession(t)
		futureTime := time.Now().Add(30 * time.Minute)
		session.ExpiresAt = futureTime

		token, err := session.Sign(privateKey)
		require.NoError(t, err)

		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		require.NoError(t, err)

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok)

		exp, ok := claims["exp"].(float64)
		require.True(t, ok)
		assert.Equal(t, futureTime.Unix(), int64(exp))
	})

	t.Run("SignatureAlgorithm", func(t *testing.T) {
		session := createValidSession(t)

		token, err := session.Sign(privateKey)
		require.NoError(t, err)

		// Parse without verification to check algorithm
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, jwt.SigningMethodEdDSA.Alg(), parsedToken.Header["alg"])
	})
}

func TestParseSession(t *testing.T) {
	// Generate test keys
	_, currentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	currentPublicKey := currentPrivateKey.Public()

	_, previousPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	previousPublicKey := previousPrivateKey.Public()

	t.Run("ParseValidTokenWithCurrentKey", func(t *testing.T) {
		session := createValidSession(t)

		token, err := session.Sign(currentPrivateKey)
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(token, currentPublicKey, previousPublicKey)
		require.NoError(t, err)
		assert.False(t, replace) // Should not need replacement
		assert.Equal(t, session.Identifier, parsedSession.Identifier)
		assert.Equal(t, session.OrganizationInfo, parsedSession.OrganizationInfo)
		assert.Equal(t, session.UserInfo, parsedSession.UserInfo)
		assert.Equal(t, session.Generation, parsedSession.Generation)
		assert.WithinDuration(t, session.ExpiresAt, parsedSession.ExpiresAt, time.Second)
	})

	t.Run("ParseValidTokenWithPreviousKey", func(t *testing.T) {
		session := createValidSession(t)

		// Sign with previous key
		token, err := session.Sign(previousPrivateKey)
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(token, currentPublicKey, previousPublicKey)
		require.NoError(t, err)
		assert.True(t, replace) // Should indicate replacement needed
		assert.Equal(t, session.Identifier, parsedSession.Identifier)
		assert.Equal(t, session.OrganizationInfo, parsedSession.OrganizationInfo)
		assert.Equal(t, session.UserInfo, parsedSession.UserInfo)
		assert.Equal(t, session.Generation, parsedSession.Generation)
	})

	t.Run("ParseExpiredToken", func(t *testing.T) {
		session := createValidSession(t)
		session.ExpiresAt = time.Now().Add(-time.Hour) // Already expired

		// Force sign even though invalid (for testing)
		claims := jwt.MapClaims{
			"sub":                     session.Identifier,
			"iss":                     session.OrganizationInfo.Identifier,
			"aud":                     session.UserInfo.Identifier,
			"exp":                     session.ExpiresAt.Unix(),
			"iat":                     time.Now().Unix(),
			"organization_identifier": session.OrganizationInfo.Identifier,
			"organization_is_default": session.OrganizationInfo.IsDefault,
			"organization_role":       session.OrganizationInfo.Role,
			"user_identifier":         session.UserInfo.Identifier,
			"user_name":               session.UserInfo.Name,
			"user_email":              session.UserInfo.Email,
			"generation":              session.Generation,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		signedToken, err := token.SignedString(currentPrivateKey)
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)
	})

	t.Run("ParseTokenWithWrongKey", func(t *testing.T) {
		session := createValidSession(t)

		// Generate a third key that's not current or previous
		_, wrongPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		token, err := session.Sign(wrongPrivateKey)
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(token, currentPublicKey, previousPublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)
	})

	t.Run("ParseMalformedToken", func(t *testing.T) {
		malformedTokens := []string{
			"not.a.token",
			"invalid",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.invalid",
			"",
			"...",
		}

		for _, token := range malformedTokens {
			parsedSession, replace, err := ParseSession(token, currentPublicKey, previousPublicKey)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrParsingSession)
			assert.False(t, replace)
			assert.Equal(t, Session{}, parsedSession)
		}
	})

	t.Run("ParseTokenWithMissingClaims", func(t *testing.T) {
		// Test various missing claims
		testCases := []struct {
			name         string
			modifyClaims func(claims jwt.MapClaims)
		}{
			{
				name: "MissingSub",
				modifyClaims: func(claims jwt.MapClaims) {
					delete(claims, "sub")
				},
			},
			{
				name: "MissingIss",
				modifyClaims: func(claims jwt.MapClaims) {
					delete(claims, "iss")
				},
			},
			{
				name: "MissingAud",
				modifyClaims: func(claims jwt.MapClaims) {
					delete(claims, "aud")
				},
			},
			{
				name: "MissingOrganizationIdentifier",
				modifyClaims: func(claims jwt.MapClaims) {
					delete(claims, "organization_identifier")
				},
			},
			{
				name: "MissingUserEmail",
				modifyClaims: func(claims jwt.MapClaims) {
					delete(claims, "user_email")
				},
			},
			{
				name: "MissingGeneration",
				modifyClaims: func(claims jwt.MapClaims) {
					delete(claims, "generation")
				},
			},
			{
				name: "MissingExp",
				modifyClaims: func(claims jwt.MapClaims) {
					delete(claims, "exp")
				},
			},
			{
				name: "InvalidRole",
				modifyClaims: func(claims jwt.MapClaims) {
					claims["organization_role"] = "invalid-role"
				},
			},
			{
				name: "EmptyEmail",
				modifyClaims: func(claims jwt.MapClaims) {
					claims["user_email"] = ""
				},
			},
			{
				name: "IssMismatch",
				modifyClaims: func(claims jwt.MapClaims) {
					claims["iss"] = uuid.New().String() // Different from organization_identifier
				},
			},
			{
				name: "AudMismatch",
				modifyClaims: func(claims jwt.MapClaims) {
					claims["aud"] = uuid.New().String() // Different from user_identifier
				},
			},
			{
				name: "ShortIdentifier",
				modifyClaims: func(claims jwt.MapClaims) {
					claims["sub"] = "too-short"
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				session := createValidSession(t)

				claims := jwt.MapClaims{
					"sub":                     session.Identifier,
					"iss":                     session.OrganizationInfo.Identifier,
					"aud":                     session.UserInfo.Identifier,
					"exp":                     session.ExpiresAt.Unix(),
					"iat":                     time.Now().Unix(),
					"organization_identifier": session.OrganizationInfo.Identifier,
					"organization_is_default": session.OrganizationInfo.IsDefault,
					"organization_role":       session.OrganizationInfo.Role,
					"user_identifier":         session.UserInfo.Identifier,
					"user_name":               session.UserInfo.Name,
					"user_email":              session.UserInfo.Email,
					"generation":              session.Generation,
				}

				tc.modifyClaims(claims)

				token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
				signedToken, err := token.SignedString(currentPrivateKey)
				require.NoError(t, err)

				parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrParsingSession)
				assert.False(t, replace)
				assert.Equal(t, Session{}, parsedSession)
			})
		}
	})

	t.Run("ParseTokenWithWrongAlgorithm", func(t *testing.T) {
		session := createValidSession(t)

		// Try to use HMAC instead of EdDSA
		claims := jwt.MapClaims{
			"sub":                     session.Identifier,
			"iss":                     session.OrganizationInfo.Identifier,
			"aud":                     session.UserInfo.Identifier,
			"exp":                     session.ExpiresAt.Unix(),
			"iat":                     time.Now().Unix(),
			"organization_identifier": session.OrganizationInfo.Identifier,
			"organization_is_default": session.OrganizationInfo.IsDefault,
			"organization_role":       session.OrganizationInfo.Role,
			"user_identifier":         session.UserInfo.Identifier,
			"user_name":               session.UserInfo.Name,
			"user_email":              session.UserInfo.Email,
			"generation":              session.Generation,
		}

		// Sign with HMAC
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)
	})

	t.Run("ParseTamperedToken", func(t *testing.T) {
		session := createValidSession(t)

		token, err := session.Sign(currentPrivateKey)
		require.NoError(t, err)

		// Tamper with the token by changing a character in the signature
		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)

		// Modify the signature
		signature := parts[2]
		if len(signature) > 0 {
			tamperedSig := []byte(signature)
			// Simply XOR with a value to tamper
			tamperedSig[0] = tamperedSig[0] ^ 0xFF
			parts[2] = string(tamperedSig)
		}

		tamperedToken := strings.Join(parts, ".")

		parsedSession, replace, err := ParseSession(tamperedToken, currentPublicKey, previousPublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)
	})

	t.Run("ParseTokenWithNilKeys", func(t *testing.T) {
		session := createValidSession(t)

		token, err := session.Sign(currentPrivateKey)
		require.NoError(t, err)

		// Try with nil current key
		parsedSession, replace, err := ParseSession(token, nil, previousPublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)

		// Try with nil previous key (should still work if signed with current)
		parsedSession, replace, err = ParseSession(token, currentPublicKey, nil)
		require.NoError(t, err)
		assert.False(t, replace)
		assert.Equal(t, session.Identifier, parsedSession.Identifier)
	})

	t.Run("ParseTokenWithWrongKeyType", func(t *testing.T) {
		session := createValidSession(t)

		token, err := session.Sign(currentPrivateKey)
		require.NoError(t, err)

		// Try to use RSA key instead of Ed25519
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(token, rsaKey.Public(), previousPublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)
	})

	t.Run("ParseTokenNotYetValid", func(t *testing.T) {
		session := createValidSession(t)

		// Create token with future nbf (not before) claim
		claims := jwt.MapClaims{
			"sub":                     session.Identifier,
			"iss":                     session.OrganizationInfo.Identifier,
			"aud":                     session.UserInfo.Identifier,
			"exp":                     session.ExpiresAt.Unix(),
			"iat":                     time.Now().Unix(),
			"nbf":                     time.Now().Add(time.Hour).Unix(), // Not valid yet
			"organization_identifier": session.OrganizationInfo.Identifier,
			"organization_is_default": session.OrganizationInfo.IsDefault,
			"organization_role":       session.OrganizationInfo.Role,
			"user_identifier":         session.UserInfo.Identifier,
			"user_name":               session.UserInfo.Name,
			"user_email":              session.UserInfo.Email,
			"generation":              session.Generation,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		signedToken, err := token.SignedString(currentPrivateKey)
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)
	})

	t.Run("KeyRotationScenario", func(t *testing.T) {
		// Simulate a real key rotation scenario
		session1 := createValidSession(t)
		session1.Generation = 1

		// Sign with previous key
		token1, err := session1.Sign(previousPrivateKey)
		require.NoError(t, err)

		// Parse should indicate replacement needed
		parsedSession1, replace1, err := ParseSession(token1, currentPublicKey, previousPublicKey)
		require.NoError(t, err)
		assert.True(t, replace1)
		assert.Equal(t, session1.Generation, parsedSession1.Generation)

		// Create new session with incremented generation
		session2 := parsedSession1
		session2.Generation++

		// Sign with current key
		token2, err := session2.Sign(currentPrivateKey)
		require.NoError(t, err)

		// Parse should not need replacement
		parsedSession2, replace2, err := ParseSession(token2, currentPublicKey, previousPublicKey)
		require.NoError(t, err)
		assert.False(t, replace2)
		assert.Equal(t, session2.Generation, parsedSession2.Generation)
	})

	t.Run("ParseWithBothKeysInvalid", func(t *testing.T) {
		session := createValidSession(t)

		// Sign with a completely different key
		_, differentKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		token, err := session.Sign(differentKey)
		require.NoError(t, err)

		// Try to parse with two other wrong keys
		_, wrongKey1, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, wrongKey2, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		parsedSession, replace, err := ParseSession(token, wrongKey1.Public(), wrongKey2.Public())
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrParsingSession)
		assert.False(t, replace)
		assert.Equal(t, Session{}, parsedSession)
	})

	t.Run("SecurityEdgeCases", func(t *testing.T) {
		t.Run("NoneAlgorithmAttack", func(t *testing.T) {
			// Try to use "none" algorithm (unsigned token)
			session := createValidSession(t)

			claims := jwt.MapClaims{
				"sub":                     session.Identifier,
				"iss":                     session.OrganizationInfo.Identifier,
				"aud":                     session.UserInfo.Identifier,
				"exp":                     session.ExpiresAt.Unix(),
				"iat":                     time.Now().Unix(),
				"organization_identifier": session.OrganizationInfo.Identifier,
				"organization_is_default": session.OrganizationInfo.IsDefault,
				"organization_role":       session.OrganizationInfo.Role,
				"user_identifier":         session.UserInfo.Identifier,
				"user_name":               session.UserInfo.Name,
				"user_email":              session.UserInfo.Email,
				"generation":              session.Generation,
			}

			token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
			unsignedToken, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
			require.NoError(t, err)

			parsedSession, replace, err := ParseSession(unsignedToken, currentPublicKey, previousPublicKey)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrParsingSession)
			assert.False(t, replace)
			assert.Equal(t, Session{}, parsedSession)
		})

		t.Run("SQLInjectionInClaims", func(t *testing.T) {
			session := createValidSession(t)
			session.UserInfo.Name = "'; DROP TABLE users; --"

			token, err := session.Sign(currentPrivateKey)
			require.NoError(t, err)

			// Should parse successfully - the injection attempt is just data
			parsedSession, replace, err := ParseSession(token, currentPublicKey, previousPublicKey)
			require.NoError(t, err)
			assert.False(t, replace)
			assert.Equal(t, session.UserInfo.Name, parsedSession.UserInfo.Name)
		})

		t.Run("XSSInClaims", func(t *testing.T) {
			session := createValidSession(t)
			session.UserInfo.Name = "<script>alert('XSS')</script>"

			token, err := session.Sign(currentPrivateKey)
			require.NoError(t, err)

			// Should parse successfully - the XSS attempt is just data
			parsedSession, replace, err := ParseSession(token, currentPublicKey, previousPublicKey)
			require.NoError(t, err)
			assert.False(t, replace)
			assert.Equal(t, session.UserInfo.Name, parsedSession.UserInfo.Name)
		})

		t.Run("ExtremelyLongClaims", func(t *testing.T) {
			session := createValidSession(t)
			// Create a very long name (but not unreasonably long to cause issues)
			session.UserInfo.Name = strings.Repeat("A", 10000)

			token, err := session.Sign(currentPrivateKey)
			require.NoError(t, err)

			parsedSession, replace, err := ParseSession(token, currentPublicKey, previousPublicKey)
			require.NoError(t, err)
			assert.False(t, replace)
			assert.Equal(t, session.UserInfo.Name, parsedSession.UserInfo.Name)
		})
	})

	t.Run("TypeConversionEdgeCases", func(t *testing.T) {
		t.Run("WrongTypeForBooleanClaim", func(t *testing.T) {
			session := createValidSession(t)

			claims := jwt.MapClaims{
				"sub":                     session.Identifier,
				"iss":                     session.OrganizationInfo.Identifier,
				"aud":                     session.UserInfo.Identifier,
				"exp":                     session.ExpiresAt.Unix(),
				"iat":                     time.Now().Unix(),
				"organization_identifier": session.OrganizationInfo.Identifier,
				"organization_is_default": "true", // String instead of boolean
				"organization_role":       session.OrganizationInfo.Role,
				"user_identifier":         session.UserInfo.Identifier,
				"user_name":               session.UserInfo.Name,
				"user_email":              session.UserInfo.Email,
				"generation":              session.Generation,
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			signedToken, err := token.SignedString(currentPrivateKey)
			require.NoError(t, err)

			parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrParsingSession)
			assert.ErrorIs(t, err, ErrInvalidClaims)
			assert.False(t, replace)
			assert.Equal(t, Session{}, parsedSession)
		})

		t.Run("WrongTypeForGenerationClaim", func(t *testing.T) {
			session := createValidSession(t)

			claims := jwt.MapClaims{
				"sub":                     session.Identifier,
				"iss":                     session.OrganizationInfo.Identifier,
				"aud":                     session.UserInfo.Identifier,
				"exp":                     session.ExpiresAt.Unix(),
				"iat":                     time.Now().Unix(),
				"organization_identifier": session.OrganizationInfo.Identifier,
				"organization_is_default": session.OrganizationInfo.IsDefault,
				"organization_role":       session.OrganizationInfo.Role,
				"user_identifier":         session.UserInfo.Identifier,
				"user_name":               session.UserInfo.Name,
				"user_email":              session.UserInfo.Email,
				"generation":              "1", // String instead of float64
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			signedToken, err := token.SignedString(currentPrivateKey)
			require.NoError(t, err)

			parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrParsingSession)
			assert.ErrorIs(t, err, ErrInvalidClaims)
			assert.False(t, replace)
			assert.Equal(t, Session{}, parsedSession)
		})

		t.Run("FloatGenerationValue", func(t *testing.T) {
			session := createValidSession(t)

			// JWT library stores numbers as float64
			claims := jwt.MapClaims{
				"sub":                     session.Identifier,
				"iss":                     session.OrganizationInfo.Identifier,
				"aud":                     session.UserInfo.Identifier,
				"exp":                     session.ExpiresAt.Unix(),
				"iat":                     time.Now().Unix(),
				"organization_identifier": session.OrganizationInfo.Identifier,
				"organization_is_default": session.OrganizationInfo.IsDefault,
				"organization_role":       session.OrganizationInfo.Role,
				"user_identifier":         session.UserInfo.Identifier,
				"user_name":               session.UserInfo.Name,
				"user_email":              session.UserInfo.Email,
				"generation":              float64(42), // Float that can be converted to uint32
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			signedToken, err := token.SignedString(currentPrivateKey)
			require.NoError(t, err)

			parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
			require.NoError(t, err)
			assert.False(t, replace)
			assert.Equal(t, uint32(42), parsedSession.Generation)
		})

		t.Run("GenerationBoundaryChecks", func(t *testing.T) {
			testCases := []struct {
				name          string
				generation    float64
				expectError   bool
				expectedValue uint32
			}{
				{name: "Zero", generation: 0, expectError: false, expectedValue: 0},
				{name: "MaxUint32", generation: float64(math.MaxUint32), expectError: false, expectedValue: math.MaxUint32},
				{name: "JustBelowMaxUint32", generation: float64(math.MaxUint32 - 1), expectError: false, expectedValue: math.MaxUint32 - 1},
				{name: "JustAboveMaxUint32", generation: float64(math.MaxUint32) + 1, expectError: true, expectedValue: 0},
				{name: "Negative", generation: -1, expectError: true, expectedValue: 0},
				{name: "LargeNegative", generation: -1000000, expectError: true, expectedValue: 0},
				{name: "VeryLarge", generation: float64(math.MaxUint64), expectError: true, expectedValue: 0},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					session := createValidSession(t)

					claims := jwt.MapClaims{
						"sub":                     session.Identifier,
						"iss":                     session.OrganizationInfo.Identifier,
						"aud":                     session.UserInfo.Identifier,
						"exp":                     session.ExpiresAt.Unix(),
						"iat":                     time.Now().Unix(),
						"organization_identifier": session.OrganizationInfo.Identifier,
						"organization_is_default": session.OrganizationInfo.IsDefault,
						"organization_role":       session.OrganizationInfo.Role,
						"user_identifier":         session.UserInfo.Identifier,
						"user_name":               session.UserInfo.Name,
						"user_email":              session.UserInfo.Email,
						"generation":              tc.generation,
					}

					token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
					signedToken, err := token.SignedString(currentPrivateKey)
					require.NoError(t, err)

					parsedSession, replace, err := ParseSession(signedToken, currentPublicKey, previousPublicKey)
					if tc.expectError {
						assert.Error(t, err)
						assert.ErrorIs(t, err, ErrParsingSession)
						assert.ErrorIs(t, err, ErrInvalidClaims)
						assert.False(t, replace)
						assert.Equal(t, Session{}, parsedSession)
					} else {
						require.NoError(t, err)
						assert.False(t, replace)
						assert.Equal(t, tc.expectedValue, parsedSession.Generation)
					}
				})
			}
		})
	})
}
