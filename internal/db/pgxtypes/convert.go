//SPDX-License-Identifier: Apache-2.0

package pgxtypes

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// UUIDFromString converts a string UUID to pgtype.UUID
func UUIDFromString(s string) pgtype.UUID {
	uid, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{
		Bytes: uid,
		Valid: true,
	}
}

// UUIDFromStringPtr converts a string pointer to pgtype.UUID, handling nil
func UUIDFromStringPtr(s *string) pgtype.UUID {
	if s == nil || *s == "" {
		return pgtype.UUID{Valid: false}
	}
	return UUIDFromString(*s)
}

// StringFromUUID converts pgtype.UUID to string
func StringFromUUID(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	// Format the bytes as a UUID string
	uid, err := uuid.FromBytes(u.Bytes[:])
	if err != nil {
		return ""
	}
	return uid.String()
}

// TimestampFromTime converts time.Time to pgtype.Timestamp
func TimestampFromTime(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{
		Time:             t.UTC(), // Ensure UTC for consistency
		InfinityModifier: pgtype.Finite,
		Valid:            true,
	}
}

// TimestampFromTimePtr converts time.Time pointer to pgtype.Timestamp, handling nil
func TimestampFromTimePtr(t *time.Time) pgtype.Timestamp {
	if t == nil {
		return pgtype.Timestamp{Valid: false}
	}
	return TimestampFromTime(*t)
}

// TimeFromTimestamp converts pgtype.Timestamp to time.Time
func TimeFromTimestamp(ts pgtype.Timestamp) time.Time {
	if !ts.Valid {
		return time.Time{}
	}
	return ts.Time
}

// NewUUID generates a new pgtype.UUID
func NewUUID() pgtype.UUID {
	return UUIDFromString(uuid.New().String())
}

// IsValidUUID checks if a pgtype.UUID is valid and not empty
func IsValidUUID(u pgtype.UUID) bool {
	return u.Valid
}

// UUIDToBytes converts a string UUID to a UUID bytes representation for salt fields
func UUIDToBytes(s string) ([16]byte, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return [16]byte{}, err
	}
	return u, nil
}
