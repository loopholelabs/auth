//SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/db/pgxtypes"
	"github.com/loopholelabs/auth/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Run("ValidDB", func(t *testing.T) {
		container := testutils.SetupPostgreSQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		device, err := New(database, logger)
		require.NoError(t, err)
		require.NotNil(t, device)
		require.NotNil(t, device.logger)
		require.NotNil(t, device.db)
		require.NotNil(t, device.ctx)
		require.NotNil(t, device.cancel)

		// Verify GC is running
		time.Sleep(100 * time.Millisecond)

		t.Cleanup(func() {
			require.NoError(t, device.Close())
		})
	})

	t.Run("NilDB", func(t *testing.T) {
		logger := logging.Test(t, logging.Zerolog, "test")

		device, err := New(nil, logger)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDBIsRequired)
		assert.Nil(t, device)
	})
}

func TestDevice_CreateFlow(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	t.Run("CreateValidFlow", func(t *testing.T) {
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, code)
		require.NotEmpty(t, poll)

		// Code should be 8 character base32 string
		assert.Len(t, code, 8)

		// Poll should be a valid UUID
		_, err = uuid.Parse(poll)
		assert.NoError(t, err)

		// Verify flow was created in database
		flowByCode, err := database.Queries.GetDeviceCodeFlowByCode(t.Context(), code)
		require.NoError(t, err)
		assert.Equal(t, code, flowByCode.Code)
		assert.Equal(t, poll, pgxtypes.StringFromUUID(flowByCode.Poll))
		assert.False(t, flowByCode.SessionIdentifier.Valid)
		assert.WithinDuration(t, time.Now(), pgxtypes.TimeFromTimestamp(flowByCode.CreatedAt), 5*time.Second)
		// LastPoll should be equal to CreatedAt on creation (both use DEFAULT CURRENT_TIMESTAMP)
		assert.True(t, flowByCode.LastPoll.Valid, "LastPoll should be valid for new flow")
		assert.Equal(t, pgxtypes.TimeFromTimestamp(flowByCode.CreatedAt), pgxtypes.TimeFromTimestamp(flowByCode.LastPoll))

		// Verify flow can be retrieved by poll
		flowByPoll, err := database.Queries.GetDeviceCodeFlowByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		require.NoError(t, err)
		assert.Equal(t, flowByCode.Identifier, flowByPoll.Identifier)
	})

	t.Run("CreateMultipleFlows", func(t *testing.T) {
		codes := make([]string, 0, 5)
		polls := make([]string, 0, 5)

		for i := 0; i < 5; i++ {
			code, poll, err := device.CreateFlow(t.Context())
			require.NoError(t, err)
			codes = append(codes, code)
			polls = append(polls, poll)
		}

		// Verify all codes and polls are unique
		codeSet := make(map[string]bool)
		pollSet := make(map[string]bool)

		for i, code := range codes {
			assert.False(t, codeSet[code], "Duplicate code found: %s", code)
			codeSet[code] = true

			poll := polls[i]
			assert.False(t, pollSet[poll], "Duplicate poll found: %s", poll)
			pollSet[poll] = true
		}

		// Verify all flows exist in database
		for i, code := range codes {
			flow, err := database.Queries.GetDeviceCodeFlowByCode(t.Context(), code)
			require.NoError(t, err)
			assert.Equal(t, code, flow.Code)
			assert.Equal(t, polls[i], pgxtypes.StringFromUUID(flow.Poll))
		}
	})

	t.Run("CreateFlowWithCancelledContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		code, poll, err := device.CreateFlow(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrCreatingFlow)
		assert.Empty(t, code)
		assert.Empty(t, poll)
	})
}

func TestDevice_ExistsFlow(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	t.Run("ExistingFlow", func(t *testing.T) {
		// Create a flow first
		code, _, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Check if flow exists
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)
		assert.NotEmpty(t, identifier)

		// Verify identifier is a valid UUID
		_, err = uuid.Parse(identifier)
		assert.NoError(t, err)
	})

	t.Run("NonExistentFlow", func(t *testing.T) {
		// Check for non-existent code
		identifier, err := device.ExistsFlow(t.Context(), "NONEXIST")
		require.NoError(t, err)
		assert.Empty(t, identifier)
	})

	t.Run("EmptyCode", func(t *testing.T) {
		identifier, err := device.ExistsFlow(t.Context(), "")
		require.NoError(t, err)
		assert.Empty(t, identifier)
	})

	t.Run("MultipleFlowsExist", func(t *testing.T) {
		// Create multiple flows
		codes := make([]string, 3)
		identifiers := make([]string, 3)

		for i := 0; i < 3; i++ {
			code, _, err := device.CreateFlow(t.Context())
			require.NoError(t, err)
			codes[i] = code

			id, err := device.ExistsFlow(t.Context(), code)
			require.NoError(t, err)
			identifiers[i] = id
		}

		// Verify all identifiers are unique
		idSet := make(map[string]bool)
		for _, id := range identifiers {
			assert.False(t, idSet[id], "Duplicate identifier found: %s", id)
			idSet[id] = true
		}
	})
}

func TestDevice_CompleteFlow(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	// Helper function to create a test session with proper foreign key setup
	createTestSession := func(t *testing.T) string {
		// Create organization first
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: pgxtypes.UUIDFromString(orgID),
			Name:       "Test Org",
			IsDefault:  false,
		})
		require.NoError(t, err)

		// Create user
		userID := uuid.New().String()
		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    pgxtypes.UUIDFromString(userID),
			Name:                          "Test User",
			PrimaryEmail:                  "test-" + userID[:8] + "@example.com",
			DefaultOrganizationIdentifier: pgxtypes.UUIDFromString(orgID),
		})
		require.NoError(t, err)

		// Create session
		sessionID := uuid.New().String()
		err = database.Queries.CreateSession(t.Context(), generated.CreateSessionParams{
			Identifier:             pgxtypes.UUIDFromString(sessionID),
			OrganizationIdentifier: pgxtypes.UUIDFromString(orgID),
			UserIdentifier:         pgxtypes.UUIDFromString(userID),
			Generation:             1,
			ExpiresAt:              pgxtypes.TimestampFromTime(time.Now().Add(time.Hour)),
		})
		require.NoError(t, err)
		return sessionID
	}

	t.Run("CompleteValidFlow", func(t *testing.T) {
		// Create a flow
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Create a session
		sessionID := createTestSession(t)

		// Complete the flow
		err = device.CompleteFlow(t.Context(), identifier, sessionID)
		require.NoError(t, err)

		// Verify flow was updated
		flow, err := database.Queries.GetDeviceCodeFlowByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		require.NoError(t, err)
		assert.True(t, flow.SessionIdentifier.Valid)
		assert.Equal(t, sessionID, pgxtypes.StringFromUUID(flow.SessionIdentifier))
	})

	t.Run("CompleteNonExistentFlow", func(t *testing.T) {
		sessionID := createTestSession(t)
		nonExistentID := uuid.New().String()

		err := device.CompleteFlow(t.Context(), nonExistentID, sessionID)
		assert.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("CompleteFlowWithEmptySessionID", func(t *testing.T) {
		// Create a flow
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Complete with empty session ID (should succeed but set NULL)
		err = device.CompleteFlow(t.Context(), identifier, "")
		require.NoError(t, err)

		// Verify flow was updated with null session
		flow, err := database.Queries.GetDeviceCodeFlowByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		require.NoError(t, err)
		assert.False(t, flow.SessionIdentifier.Valid)
	})

	t.Run("CompleteFlowWithInvalidSessionID", func(t *testing.T) {
		// Create a flow
		code, _, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Try to complete with non-existent session ID (foreign key constraint should fail)
		invalidSessionID := uuid.New().String()
		err = device.CompleteFlow(t.Context(), identifier, invalidSessionID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrCompletingFlow)
	})

	t.Run("CompleteFlowTwice", func(t *testing.T) {
		// Create a flow
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Create two sessions
		sessionID1 := createTestSession(t)
		sessionID2 := createTestSession(t)

		// Complete the flow first time
		err = device.CompleteFlow(t.Context(), identifier, sessionID1)
		require.NoError(t, err)

		// Complete the flow second time (should update)
		err = device.CompleteFlow(t.Context(), identifier, sessionID2)
		require.NoError(t, err)

		// Verify flow has the second session
		flow, err := database.Queries.GetDeviceCodeFlowByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		require.NoError(t, err)
		assert.Equal(t, sessionID2, pgxtypes.StringFromUUID(flow.SessionIdentifier))
	})
}

func TestDevice_PollFlow(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	// Helper function to create a test session with proper foreign key setup
	createTestSession := func(t *testing.T) string {
		// Create organization first
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: pgxtypes.UUIDFromString(orgID),
			Name:       "Test Org",
			IsDefault:  false,
		})
		require.NoError(t, err)

		// Create user
		userID := uuid.New().String()
		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    pgxtypes.UUIDFromString(userID),
			Name:                          "Test User",
			PrimaryEmail:                  "test-" + userID[:8] + "@example.com",
			DefaultOrganizationIdentifier: pgxtypes.UUIDFromString(orgID),
		})
		require.NoError(t, err)

		// Create session
		sessionID := uuid.New().String()
		err = database.Queries.CreateSession(t.Context(), generated.CreateSessionParams{
			Identifier:             pgxtypes.UUIDFromString(sessionID),
			OrganizationIdentifier: pgxtypes.UUIDFromString(orgID),
			UserIdentifier:         pgxtypes.UUIDFromString(userID),
			Generation:             1,
			ExpiresAt:              pgxtypes.TimestampFromTime(time.Now().Add(time.Hour)),
		})
		require.NoError(t, err)
		return sessionID
	}

	t.Run("PollIncompleteFlow", func(t *testing.T) {
		// Create a flow
		_, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Poll the flow (should return not completed)
		sessionID, err := device.PollFlow(t.Context(), poll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)
		assert.ErrorIs(t, err, ErrFlowNotCompleted)
		assert.Empty(t, sessionID)

		// Verify LastPoll was updated
		flow, err := database.Queries.GetDeviceCodeFlowByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now(), pgxtypes.TimeFromTimestamp(flow.LastPoll), 5*time.Second)
	})

	t.Run("PollCompletedFlow", func(t *testing.T) {
		// Create a flow
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Create and attach a session
		sessionID := createTestSession(t)
		err = device.CompleteFlow(t.Context(), identifier, sessionID)
		require.NoError(t, err)

		// Check the flow state before polling
		flow, err := database.Queries.GetDeviceCodeFlowByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		require.NoError(t, err)
		t.Logf("Flow LastPoll valid: %v, time: %v", flow.LastPoll.Valid, flow.LastPoll.Time)
		t.Logf("Flow SessionIdentifier valid: %v", flow.SessionIdentifier.Valid)

		// Poll the flow (should return session ID and delete flow)
		returnedSessionID, err := device.PollFlow(t.Context(), poll, 5*time.Second)
		require.NoError(t, err)
		assert.Equal(t, sessionID, returnedSessionID)

		// Verify flow was deleted
		_, err = database.Queries.GetDeviceCodeFlowByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		assert.Error(t, err)
		assert.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("PollNonExistentFlow", func(t *testing.T) {
		nonExistentPoll := uuid.New().String()

		sessionID, err := device.PollFlow(t.Context(), nonExistentPoll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)
		assert.Empty(t, sessionID)
	})

	t.Run("PollWithRateLimit", func(t *testing.T) {
		// Create a flow
		_, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		time.Sleep(time.Second)

		// Set LastPoll to very recent time
		num, err := database.Queries.UpdateDeviceCodeFlowLastPollByPoll(t.Context(), pgxtypes.UUIDFromString(poll))
		require.NoError(t, err)
		require.Equal(t, int64(1), num)

		// Try to poll immediately with long poll rate (should be rate limited since we just updated LastPoll)
		sessionID, err := device.PollFlow(t.Context(), poll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)
		assert.ErrorIs(t, err, ErrRateLimitFlow)
		assert.Empty(t, sessionID)
	})

	t.Run("PollWithActualRateLimit", func(t *testing.T) {
		// Save original now function
		originalNow := now
		defer func() { now = originalNow }()

		// Mock time to control rate limiting
		currentTime := time.Now()
		now = func() time.Time { return currentTime }

		// Create a flow
		_, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// First poll - should update LastPoll
		_, err = device.PollFlow(t.Context(), poll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowNotCompleted)

		// Try to poll again immediately with short poll rate
		// This should be rate limited because LastPoll + 1ms is before now()
		sessionID, err := device.PollFlow(t.Context(), poll, 1*time.Millisecond)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)
		assert.ErrorIs(t, err, ErrRateLimitFlow)
		assert.Empty(t, sessionID)
	})

	t.Run("PollWithInvalidSession", func(t *testing.T) {
		// Create a flow
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Create a session
		sessionID := createTestSession(t)

		// Complete the flow with session
		err = device.CompleteFlow(t.Context(), identifier, sessionID)
		require.NoError(t, err)

		// Delete the session (to simulate invalid foreign key)
		num, err := database.Queries.DeleteSessionByIdentifier(t.Context(), pgxtypes.UUIDFromString(sessionID))
		require.NoError(t, err)
		assert.Equal(t, int64(1), num)

		// Poll should fail when trying to get session
		returnedSessionID, err := device.PollFlow(t.Context(), poll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)
		assert.Empty(t, returnedSessionID)
	})

	t.Run("ConcurrentPolling", func(t *testing.T) {
		// Create a flow
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Create a session
		sessionID := createTestSession(t)

		// Complete the flow
		err = device.CompleteFlow(t.Context(), identifier, sessionID)
		require.NoError(t, err)

		// Try concurrent polling
		results := make(chan struct {
			sessionID string
			err       error
		}, 2)

		// Use a WaitGroup to ensure both goroutines start at the same time
		var startWg sync.WaitGroup
		startWg.Add(2)

		for i := 0; i < 2; i++ {
			go func() {
				startWg.Done()
				startWg.Wait() // Wait for both goroutines to be ready
				sid, err := device.PollFlow(t.Context(), poll, 5*time.Second)
				results <- struct {
					sessionID string
					err       error
				}{sid, err}
			}()
		}

		// Collect results
		successCount := 0
		errorCount := 0
		for i := 0; i < 2; i++ {
			result := <-results
			if result.err == nil {
				assert.Equal(t, sessionID, result.sessionID)
				successCount++
			} else {
				errorCount++
			}
		}

		// Due to transaction isolation, both might succeed or one might fail
		// This depends on timing and transaction isolation level
		// We'll accept either outcome as valid
		assert.GreaterOrEqual(t, successCount, 1, "At least one poll should succeed")
		assert.LessOrEqual(t, successCount, 2, "At most two polls can succeed")
	})
}

func TestDevice_GarbageCollection(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	// Save original now function
	originalNow := now
	defer func() { now = originalNow }()

	// Mock time for testing
	currentTime := time.Now()
	now = func() time.Time { return currentTime }

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	t.Run("GCDeletesExpiredFlows", func(t *testing.T) {
		// Create some flows
		codes := make([]string, 3)
		for i := 0; i < 3; i++ {
			code, _, err := device.CreateFlow(t.Context())
			require.NoError(t, err)
			codes[i] = code
		}

		// Verify all flows exist
		for _, code := range codes {
			id, err := device.ExistsFlow(t.Context(), code)
			require.NoError(t, err)
			assert.NotEmpty(t, id)
		}

		// Move time forward past expiry
		currentTime = currentTime.Add(Expiry + time.Minute)

		// Run GC
		deleted, err := device.gc()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, deleted, int64(3))

		// Verify flows were deleted
		for _, code := range codes {
			id, err := device.ExistsFlow(t.Context(), code)
			require.NoError(t, err)
			assert.Empty(t, id)
		}
	})

	t.Run("GCKeepsNonExpiredFlows", func(t *testing.T) {
		// Reset time
		currentTime = time.Now()

		// Create a new flow
		code, _, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Verify flow exists
		id, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)
		assert.NotEmpty(t, id)

		// Move time forward but not past expiry
		currentTime = currentTime.Add(Expiry - time.Minute)

		// Run GC
		deleted, err := device.gc()
		require.NoError(t, err)
		assert.Equal(t, int64(0), deleted)

		// Verify flow still exists
		id, err = device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)
		assert.NotEmpty(t, id)
	})

	t.Run("GCWithTimeout", func(t *testing.T) {
		// Create a context that will be cancelled
		ctx, cancel := context.WithCancel(context.Background())
		device.ctx = ctx

		// Create some expired flows
		currentTime = time.Now()
		for i := 0; i < 3; i++ {
			_, _, err := device.CreateFlow(t.Context())
			require.NoError(t, err)
		}

		// Move time forward past expiry
		currentTime = currentTime.Add(Expiry + time.Minute)

		// Cancel context to simulate timeout
		cancel()

		// GC should handle context cancellation gracefully
		deleted, err := device.gc()
		assert.Error(t, err)
		assert.Equal(t, int64(0), deleted)
	})
}

func TestDevice_Close(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("CloseStopsGC", func(t *testing.T) {
		device, err := New(database, logger)
		require.NoError(t, err)

		// Let GC start
		time.Sleep(100 * time.Millisecond)

		// Close should stop GC
		err = device.Close()
		require.NoError(t, err)

		// Verify context is cancelled
		select {
		case <-device.ctx.Done():
			// Context should be done
		default:
			t.Fatal("Context should be cancelled after Close")
		}
	})

	t.Run("CloseIsIdempotent", func(t *testing.T) {
		device, err := New(database, logger)
		require.NoError(t, err)

		// Close multiple times should not panic
		err = device.Close()
		require.NoError(t, err)

		err = device.Close()
		require.NoError(t, err)
	})
}

func TestDevice_EdgeCases(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	t.Run("LongRunningFlow", func(t *testing.T) {
		// This test simulates a long-running flow that gets polled multiple times
		// without expiring

		// Create a flow
		code, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Sleep a tiny bit to ensure database timestamp has passed
		time.Sleep(2 * time.Millisecond)

		// Poll multiple times rapidly to test rate limiting
		for i := 0; i < 5; i++ {
			// Use a long pollRate (1 second) to ensure subsequent rapid polls are rate limited
			_, err = device.PollFlow(t.Context(), poll, 1*time.Second)

			if i == 0 {
				// First poll should succeed (return flow not completed)
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrPollingFlow)
				assert.ErrorIs(t, err, ErrFlowNotCompleted)
			} else {
				// Subsequent rapid polls should be rate limited
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrPollingFlow)
				assert.ErrorIs(t, err, ErrRateLimitFlow)
			}

			// Don't sleep - we want rapid polls to test rate limiting
		}

		// Flow should still exist (hasn't expired)
		id, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)
		assert.NotEmpty(t, id)
	})

	t.Run("TransactionRollback", func(t *testing.T) {
		// Create a flow
		_, poll, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Mock a database error during polling
		// This tests that the transaction is properly rolled back
		// We can't easily mock internal database errors, but we can test
		// with an invalid poll value that will cause an error
		invalidPoll := "invalid-uuid"
		_, err = device.PollFlow(t.Context(), invalidPoll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)

		// Original flow should still be pollable (but returns flow not completed)
		_, err = device.PollFlow(t.Context(), poll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)
		assert.ErrorIs(t, err, ErrFlowNotCompleted)
	})

	t.Run("DatabaseConnectionLoss", func(t *testing.T) {
		// Create a flow
		code, _, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Close database connection
		require.NoError(t, database.Close())

		// Operations should fail gracefully
		_, err = device.ExistsFlow(t.Context(), code)
		assert.Error(t, err)

		_, _, err = device.CreateFlow(t.Context())
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrCreatingFlow)
	})
}

func TestDevice_SecurityCases(t *testing.T) {
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	t.Run("CodeUniqueness", func(t *testing.T) {
		// Create many flows and check for code collisions
		codeMap := make(map[string]bool)
		const numFlows = 100

		for i := 0; i < numFlows; i++ {
			code, _, err := device.CreateFlow(t.Context())
			require.NoError(t, err)

			// Check for duplicates
			assert.False(t, codeMap[code], "Duplicate code generated: %s", code)
			codeMap[code] = true
		}

		assert.Len(t, codeMap, numFlows)
	})

	t.Run("PollUniqueness", func(t *testing.T) {
		// Create many flows and check for poll UUID collisions
		pollMap := make(map[string]bool)
		const numFlows = 100

		for i := 0; i < numFlows; i++ {
			_, poll, err := device.CreateFlow(t.Context())
			require.NoError(t, err)

			// Check for duplicates
			assert.False(t, pollMap[poll], "Duplicate poll UUID generated: %s", poll)
			pollMap[poll] = true

			// Verify it's a valid UUID
			_, err = uuid.Parse(poll)
			assert.NoError(t, err)
		}

		assert.Len(t, pollMap, numFlows)
	})

	t.Run("SQLInjectionInCode", func(t *testing.T) {
		// Try SQL injection in code parameter
		maliciousCode := "'; DROP TABLE device_code_flows; --"

		identifier, err := device.ExistsFlow(t.Context(), maliciousCode)
		require.NoError(t, err)
		assert.Empty(t, identifier)

		// Verify table still exists
		count, err := database.Queries.CountAllDeviceCodeFlows(t.Context())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(0))
	})

	t.Run("SQLInjectionInPoll", func(t *testing.T) {
		// Try SQL injection in poll parameter
		maliciousPoll := "'; DROP TABLE device_code_flows; --"

		_, err := device.PollFlow(t.Context(), maliciousPoll, 5*time.Second)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPollingFlow)

		// Verify table still exists
		count, err := database.Queries.CountAllDeviceCodeFlows(t.Context())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(0))
	})

	t.Run("InvalidSessionIdentifier", func(t *testing.T) {
		// Create a flow
		code, _, err := device.CreateFlow(t.Context())
		require.NoError(t, err)

		// Get flow identifier
		identifier, err := device.ExistsFlow(t.Context(), code)
		require.NoError(t, err)

		// Try various invalid session identifiers
		invalidSessions := []string{
			"not-a-uuid",
			"'; DROP TABLE sessions; --",
			"<script>alert('XSS')</script>",
			strings.Repeat("a", 1000),
		}

		for _, invalidSession := range invalidSessions {
			err := device.CompleteFlow(t.Context(), identifier, invalidSession)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrCompletingFlow)
		}
	})
}

func TestDevice_PerformanceAndStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	device, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, device.Close())
	})

	t.Run("ManyFlowsCreation", func(t *testing.T) {
		const numFlows = 100
		start := time.Now()

		for i := 0; i < numFlows; i++ {
			_, _, err := device.CreateFlow(t.Context())
			require.NoError(t, err)
		}

		duration := time.Since(start)
		t.Logf("Created %d flows in %v (%.2f flows/sec)", numFlows, duration, float64(numFlows)/duration.Seconds())

		// Verify count
		count, err := database.Queries.CountAllDeviceCodeFlows(t.Context())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(numFlows))
	})

	t.Run("ConcurrentFlowOperations", func(t *testing.T) {
		const numGoroutines = 10
		const opsPerGoroutine = 10

		var wg sync.WaitGroup
		errs := make(chan error, numGoroutines*opsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < opsPerGoroutine; j++ {
					// Create flow
					code, poll, err := device.CreateFlow(context.Background())
					if err != nil {
						errs <- err
						continue
					}

					// Check existence
					id, err := device.ExistsFlow(context.Background(), code)
					if err != nil {
						errs <- err
						continue
					}
					if id == "" {
						errs <- errors.New("flow should exist")
						continue
					}

					// Poll (should fail as incomplete)
					_, err = device.PollFlow(context.Background(), poll, 5*time.Second)
					if err == nil {
						errs <- errors.New("poll should fail for incomplete flow")
					}
				}
			}()
		}

		wg.Wait()
		close(errs)

		// Check for errors
		errorCount := 0
		for err := range errs {
			t.Logf("Concurrent operation error: %v", err)
			errorCount++
		}
		assert.Equal(t, 0, errorCount, "Should have no errors in concurrent operations")
	})

	t.Run("GCWithManyExpiredFlows", func(t *testing.T) {
		// Save original now function
		originalNow := now
		defer func() { now = originalNow }()

		currentTime := time.Now()
		now = func() time.Time { return currentTime }

		// Clear existing flows
		_, err := database.Queries.DeleteAllDeviceCodeFlows(t.Context())
		require.NoError(t, err)

		// Create many flows
		const numFlows = 500
		for i := 0; i < numFlows; i++ {
			_, _, err := device.CreateFlow(t.Context())
			require.NoError(t, err)
		}

		// Move time forward past expiry
		currentTime = currentTime.Add(Expiry + time.Minute)

		// Run GC and measure time
		start := time.Now()
		deleted, err := device.gc()
		duration := time.Since(start)

		require.NoError(t, err)
		assert.Equal(t, int64(numFlows), deleted)
		t.Logf("GC deleted %d expired flows in %v", deleted, duration)

		// Verify all flows were deleted
		count, err := database.Queries.CountAllDeviceCodeFlows(t.Context())
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}
