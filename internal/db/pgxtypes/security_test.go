//SPDX-License-Identifier: Apache-2.0

package pgxtypes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityInvalidUUIDHandling demonstrates that invalid UUID inputs are properly
// rejected before they can cause database issues or security vulnerabilities
func TestSecurityInvalidUUIDHandling(t *testing.T) {
	t.Run("EmptyStringUUID", func(t *testing.T) {
		// Previously, empty strings would create invalid UUIDs that could
		// potentially be passed to database queries, causing unexpected behavior
		result, err := UUIDFromString("")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyUUID)
		assert.False(t, result.Valid)

		// This ensures that empty strings are explicitly rejected
		// preventing potential security issues where empty values
		// might bypass validation or cause incorrect database lookups
	})

	t.Run("SQLInjectionAttemptInUUID", func(t *testing.T) {
		// Test that SQL injection attempts in UUID fields are properly rejected
		maliciousInputs := []string{
			"'; DROP TABLE users; --",
			"' OR '1'='1",
			"123e4567-e89b-12d3-a456-426614174000' OR '1'='1",
			"123e4567-e89b-12d3-a456-426614174000; DELETE FROM sessions",
		}

		for _, input := range maliciousInputs {
			result, err := UUIDFromString(input)
			assert.Error(t, err, "Malicious input should be rejected: %s", input)
			assert.False(t, result.Valid)
		}
	})

	t.Run("MalformedUUIDRejection", func(t *testing.T) {
		// Test various malformed UUIDs that should be rejected
		malformedInputs := []string{
			"not-a-uuid",
			"123",
			"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			"00000000-0000-0000-0000-00000000000g",  // Invalid character
			"00000000-0000-0000-0000-0000000000000", // Extra character
			"00000000-0000-0000-0000-0000000000",    // Missing character
		}

		for _, input := range malformedInputs {
			result, err := UUIDFromString(input)
			assert.Error(t, err, "Malformed UUID should be rejected: %s", input)
			assert.False(t, result.Valid)
		}
	})

	t.Run("NilPointerHandling", func(t *testing.T) {
		// Test that nil pointers are handled safely
		result, err := UUIDFromStringPtr(nil)
		assert.NoError(t, err) // nil is valid, returns invalid UUID
		assert.False(t, result.Valid)

		// This is important for optional fields where nil represents
		// "no value" rather than an error condition
	})

	t.Run("EmptyStringPointerHandling", func(t *testing.T) {
		// Test that empty string pointers are properly rejected
		emptyStr := ""
		result, err := UUIDFromStringPtr(&emptyStr)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyUUID)
		assert.False(t, result.Valid)
	})

	t.Run("ZeroTimeRejection", func(t *testing.T) {
		// Test that zero time values are properly rejected
		// Zero times can cause issues with time comparisons and
		// session expiry calculations
		var zeroTime time.Time
		result, err := TimestampFromTime(zeroTime)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTimestamp)
		assert.False(t, result.Valid)

		// This prevents issues where zero times might be interpreted
		// as "never expires" or cause incorrect session validation
	})

	t.Run("ValidUUIDAcceptance", func(t *testing.T) {
		// Ensure valid UUIDs are still accepted
		validUUID := "123e4567-e89b-12d3-a456-426614174000"
		result, err := UUIDFromString(validUUID)
		require.NoError(t, err)
		assert.True(t, result.Valid)

		// Convert back to string to ensure round-trip works
		strResult, err := StringFromUUID(result)
		require.NoError(t, err)
		assert.Equal(t, validUUID, strResult)
	})
}

// TestSecurityDatabaseLookupWithInvalidInput demonstrates that invalid inputs
// are caught before database operations, preventing potential security issues
func TestSecurityDatabaseLookupWithInvalidInput(t *testing.T) {
	t.Run("SessionRevocationWithInvalidID", func(t *testing.T) {
		// Simulates an API endpoint receiving an invalid session ID
		// for revocation. Previously, this might have created an invalid
		// database query or silently failed.
		sessionID := "not-a-valid-uuid"

		// Convert to UUID - this should fail
		_, err := UUIDFromString(sessionID)
		assert.Error(t, err)

		// In the actual API handler, this error would result in
		// returning a 400 Bad Request, preventing the invalid UUID
		// from reaching the database layer
	})

	t.Run("UserLookupWithEmptyID", func(t *testing.T) {
		// Simulates looking up a user with an empty identifier
		// This could occur if session data is corrupted or manipulated
		userID := ""

		// Convert to UUID - this should fail
		_, err := UUIDFromString(userID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyUUID)

		// This prevents database queries with empty/null values
		// that could return unexpected results or cause errors
	})
}
