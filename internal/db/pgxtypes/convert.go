//SPDX-License-Identifier: Apache-2.0

package pgxtypes

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrInvalidUUID      = errors.New("invalid UUID")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrEmptyUUID        = errors.New("empty UUID string")
)

// UUIDFromString converts a string UUID to pgtype.UUID
func UUIDFromString(s string) (pgtype.UUID, error) {
	if s == "" {
		return pgtype.UUID{}, ErrEmptyUUID
	}
	uid, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{
		Bytes: uid,
		Valid: true,
	}, nil
}

// UUIDFromStringPtr converts a string pointer to pgtype.UUID, handling nil
func UUIDFromStringPtr(s *string) (pgtype.UUID, error) {
	if s == nil {
		return pgtype.UUID{Valid: false}, nil // nil is valid, returns invalid UUID
	}
	if *s == "" {
		return pgtype.UUID{}, ErrEmptyUUID
	}
	return UUIDFromString(*s)
}

// StringFromUUID converts pgtype.UUID to string
func StringFromUUID(u pgtype.UUID) (string, error) {
	if !u.Valid {
		return "", ErrInvalidUUID
	}
	// Format the bytes as a UUID string
	uid, err := uuid.FromBytes(u.Bytes[:])
	if err != nil {
		return "", err
	}
	return uid.String(), nil
}

// TimestampFromTime converts time.Time to pgtype.Timestamp
func TimestampFromTime(t time.Time) (pgtype.Timestamp, error) {
	if t.IsZero() {
		return pgtype.Timestamp{}, ErrInvalidTimestamp
	}
	return pgtype.Timestamp{
		Time:             t.UTC(), // Ensure UTC for consistency
		InfinityModifier: pgtype.Finite,
		Valid:            true,
	}, nil
}

// TimestampFromTimePtr converts time.Time pointer to pgtype.Timestamp, handling nil
func TimestampFromTimePtr(t *time.Time) (pgtype.Timestamp, error) {
	if t == nil {
		return pgtype.Timestamp{Valid: false}, nil // nil is valid, returns invalid timestamp
	}
	if t.IsZero() {
		return pgtype.Timestamp{}, ErrInvalidTimestamp
	}
	return TimestampFromTime(*t)
}

// TimeFromTimestamp converts pgtype.Timestamp to time.Time
func TimeFromTimestamp(ts pgtype.Timestamp) (time.Time, error) {
	if !ts.Valid {
		return time.Time{}, ErrInvalidTimestamp
	}
	return ts.Time, nil
}

// NewUUID generates a new pgtype.UUID
func NewUUID() (pgtype.UUID, error) {
	return UUIDFromString(uuid.New().String())
}

// UUIDToBytes converts a string UUID to a UUID bytes representation for salt fields
func UUIDToBytes(s string) ([16]byte, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return [16]byte{}, err
	}
	return u, nil
}
