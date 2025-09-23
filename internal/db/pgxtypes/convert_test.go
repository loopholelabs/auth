//SPDX-License-Identifier: Apache-2.0

package pgxtypes

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUUIDFromString(t *testing.T) {
	t.Run("ValidUUID", func(t *testing.T) {
		validUUID := "123e4567-e89b-12d3-a456-426614174000"
		result := UUIDFromString(validUUID)

		assert.True(t, result.Valid)
		assert.Equal(t, validUUID, StringFromUUID(result))
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		invalidUUID := "not-a-uuid"
		result := UUIDFromString(invalidUUID)

		assert.False(t, result.Valid)
	})

	t.Run("EmptyString", func(t *testing.T) {
		result := UUIDFromString("")

		assert.False(t, result.Valid)
	})

	t.Run("MalformedUUID", func(t *testing.T) {
		malformedUUID := "123e4567-e89b-12d3-a456"
		result := UUIDFromString(malformedUUID)

		assert.False(t, result.Valid)
	})
}

func TestUUIDFromStringPtr(t *testing.T) {
	t.Run("ValidUUID", func(t *testing.T) {
		validUUID := "123e4567-e89b-12d3-a456-426614174000"
		result := UUIDFromStringPtr(&validUUID)

		assert.True(t, result.Valid)
		assert.Equal(t, validUUID, StringFromUUID(result))
	})

	t.Run("NilPointer", func(t *testing.T) {
		result := UUIDFromStringPtr(nil)

		assert.False(t, result.Valid)
	})

	t.Run("EmptyString", func(t *testing.T) {
		emptyString := ""
		result := UUIDFromStringPtr(&emptyString)

		assert.False(t, result.Valid)
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		invalidUUID := "not-a-uuid"
		result := UUIDFromStringPtr(&invalidUUID)

		assert.False(t, result.Valid)
	})
}

func TestStringFromUUID(t *testing.T) {
	t.Run("ValidUUID", func(t *testing.T) {
		validUUID := "123e4567-e89b-12d3-a456-426614174000"
		pgUUID := UUIDFromString(validUUID)
		result := StringFromUUID(pgUUID)

		assert.Equal(t, validUUID, result)
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		invalidUUID := pgtype.UUID{Valid: false}
		result := StringFromUUID(invalidUUID)

		assert.Empty(t, result)
	})

	t.Run("ValidUUIDWithInvalidBytes", func(t *testing.T) {
		// Create a UUID with invalid bytes array
		invalidUUID := pgtype.UUID{
			Bytes: [16]byte{}, // All zeros, but marked as valid
			Valid: true,
		}
		result := StringFromUUID(invalidUUID)

		// All-zero UUID should still be valid
		assert.Equal(t, "00000000-0000-0000-0000-000000000000", result)
	})
}

func TestTimestampFromTime(t *testing.T) {
	t.Run("ValidTime", func(t *testing.T) {
		now := time.Now()
		result := TimestampFromTime(now)

		assert.True(t, result.Valid)
		assert.Equal(t, pgtype.Finite, result.InfinityModifier)
		assert.Equal(t, now.UTC(), result.Time)
	})

	t.Run("ZeroTime", func(t *testing.T) {
		zeroTime := time.Time{}
		result := TimestampFromTime(zeroTime)

		assert.True(t, result.Valid)
		assert.Equal(t, pgtype.Finite, result.InfinityModifier)
		assert.Equal(t, zeroTime.UTC(), result.Time)
	})

	t.Run("TimeWithTimezone", func(t *testing.T) {
		loc, err := time.LoadLocation("America/New_York")
		require.NoError(t, err)

		nyTime := time.Date(2024, 1, 1, 12, 0, 0, 0, loc)
		result := TimestampFromTime(nyTime)

		assert.True(t, result.Valid)
		assert.Equal(t, nyTime.UTC(), result.Time)
	})
}

func TestTimestampFromTimePtr(t *testing.T) {
	t.Run("ValidTimePointer", func(t *testing.T) {
		now := time.Now()
		result := TimestampFromTimePtr(&now)

		assert.True(t, result.Valid)
		assert.Equal(t, pgtype.Finite, result.InfinityModifier)
		assert.Equal(t, now.UTC(), result.Time)
	})

	t.Run("NilPointer", func(t *testing.T) {
		result := TimestampFromTimePtr(nil)

		assert.False(t, result.Valid)
	})

	t.Run("ZeroTimePointer", func(t *testing.T) {
		zeroTime := time.Time{}
		result := TimestampFromTimePtr(&zeroTime)

		assert.True(t, result.Valid)
		assert.Equal(t, zeroTime.UTC(), result.Time)
	})
}

func TestTimeFromTimestamp(t *testing.T) {
	t.Run("ValidTimestamp", func(t *testing.T) {
		now := time.Now()
		timestamp := TimestampFromTime(now)
		result := TimeFromTimestamp(timestamp)

		assert.Equal(t, now.UTC(), result)
	})

	t.Run("InvalidTimestamp", func(t *testing.T) {
		invalidTimestamp := pgtype.Timestamp{Valid: false}
		result := TimeFromTimestamp(invalidTimestamp)

		assert.Equal(t, time.Time{}, result)
	})

	t.Run("ZeroTimestamp", func(t *testing.T) {
		zeroTime := time.Time{}
		timestamp := TimestampFromTime(zeroTime)
		result := TimeFromTimestamp(timestamp)

		assert.Equal(t, zeroTime.UTC(), result)
	})
}

func TestNewUUID(t *testing.T) {
	t.Run("GeneratesValidUUID", func(t *testing.T) {
		result := NewUUID()

		assert.True(t, result.Valid)

		// Verify it's a valid UUID string
		uuidStr := StringFromUUID(result)
		assert.NotEmpty(t, uuidStr)

		// Verify it can be parsed back
		_, err := uuid.Parse(uuidStr)
		assert.NoError(t, err)
	})

	t.Run("GeneratesUniqueUUIDs", func(t *testing.T) {
		uuid1 := NewUUID()
		uuid2 := NewUUID()

		assert.NotEqual(t, uuid1.Bytes, uuid2.Bytes)
	})
}

func TestIsValidUUID(t *testing.T) {
	t.Run("ValidUUID", func(t *testing.T) {
		validUUID := UUIDFromString("123e4567-e89b-12d3-a456-426614174000")
		assert.True(t, IsValidUUID(validUUID))
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		invalidUUID := pgtype.UUID{Valid: false}
		assert.False(t, IsValidUUID(invalidUUID))
	})

	t.Run("NewUUID", func(t *testing.T) {
		newUUID := NewUUID()
		assert.True(t, IsValidUUID(newUUID))
	})
}

func TestUUIDToBytes(t *testing.T) {
	t.Run("ValidUUID", func(t *testing.T) {
		validUUID := "123e4567-e89b-12d3-a456-426614174000"
		result, err := UUIDToBytes(validUUID)

		require.NoError(t, err)

		// Verify the bytes match the original UUID
		uid, err := uuid.Parse(validUUID)
		require.NoError(t, err)
		assert.Equal(t, [16]byte(uid), result)
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		invalidUUID := "not-a-uuid"
		_, err := UUIDToBytes(invalidUUID)

		assert.Error(t, err)
	})

	t.Run("EmptyString", func(t *testing.T) {
		_, err := UUIDToBytes("")

		assert.Error(t, err)
	})

	t.Run("MalformedUUID", func(t *testing.T) {
		malformedUUID := "123e4567-e89b-12d3-a456"
		_, err := UUIDToBytes(malformedUUID)

		assert.Error(t, err)
	})

	t.Run("ZeroUUID", func(t *testing.T) {
		zeroUUID := "00000000-0000-0000-0000-000000000000"
		result, err := UUIDToBytes(zeroUUID)

		require.NoError(t, err)
		assert.Equal(t, [16]byte{}, result)
	})
}

func TestRoundTripConversions(t *testing.T) {
	t.Run("UUID RoundTrip", func(t *testing.T) {
		original := "550e8400-e29b-41d4-a716-446655440000"

		// String -> pgtype.UUID -> String
		pgUUID := UUIDFromString(original)
		result := StringFromUUID(pgUUID)

		assert.Equal(t, original, result)
	})

	t.Run("Timestamp RoundTrip", func(t *testing.T) {
		original := time.Now().Truncate(time.Microsecond) // PostgreSQL precision

		// Time -> pgtype.Timestamp -> Time
		pgTimestamp := TimestampFromTime(original)
		result := TimeFromTimestamp(pgTimestamp)

		assert.Equal(t, original.UTC(), result)
	})

	t.Run("UUID Bytes RoundTrip", func(t *testing.T) {
		original := "550e8400-e29b-41d4-a716-446655440000"

		// String -> Bytes -> UUID -> String
		bytes, err := UUIDToBytes(original)
		require.NoError(t, err)

		uid, err := uuid.FromBytes(bytes[:])
		require.NoError(t, err)

		assert.Equal(t, original, uid.String())
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("MaxUUID", func(t *testing.T) {
		maxUUID := "ffffffff-ffff-ffff-ffff-ffffffffffff"
		result := UUIDFromString(maxUUID)

		assert.True(t, result.Valid)
		assert.Equal(t, maxUUID, StringFromUUID(result))
	})

	t.Run("FutureTimestamp", func(t *testing.T) {
		futureTime := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		result := TimestampFromTime(futureTime)

		assert.True(t, result.Valid)
		assert.Equal(t, futureTime, result.Time)
	})

	t.Run("PastTimestamp", func(t *testing.T) {
		pastTime := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
		result := TimestampFromTime(pastTime)

		assert.True(t, result.Valid)
		assert.Equal(t, pastTime, result.Time)
	})

	t.Run("MicrosecondPrecision", func(t *testing.T) {
		// PostgreSQL supports microsecond precision
		now := time.Now().Add(123456 * time.Nanosecond)
		timestamp := TimestampFromTime(now)
		result := TimeFromTimestamp(timestamp)

		// Should preserve microsecond precision
		assert.Equal(t, now.UTC().Truncate(time.Microsecond), result.Truncate(time.Microsecond))
	})
}
