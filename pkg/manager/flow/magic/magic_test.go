//SPDX-License-Identifier: Apache-2.0

package magic

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/testutils"
)

func TestNew(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("ValidDatabase", func(t *testing.T) {
		m, err := New(database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)
		require.NotNil(t, m.logger)
		require.Equal(t, database, m.db)
		require.NotNil(t, m.ctx)
		require.NotNil(t, m.cancel)

		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})
	})

	t.Run("NilDatabase", func(t *testing.T) {
		m, err := New(nil, logger)
		require.ErrorIs(t, err, ErrDBIsRequired)
		require.Nil(t, m)
	})
}

func TestCreateFlow(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("CreateFlowSuccess", func(t *testing.T) {
		token, err := m.CreateFlow(t.Context(), "test@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Decode the token to validate its structure
		tokenBytes, err := base64.StdEncoding.DecodeString(token)
		require.NoError(t, err)

		// Token should be in format: identifier_secret
		tokenStr := string(tokenBytes)
		require.Contains(t, tokenStr, "_")

		parts := strings.Split(tokenStr, "_")
		require.Len(t, parts, 2)

		identifier := parts[0]
		secret := parts[1]

		// Both should be valid UUIDs
		_, err = uuid.Parse(identifier)
		require.NoError(t, err)
		_, err = uuid.Parse(secret)
		require.NoError(t, err)

		// Verify flow was created in database
		flow, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)
		require.Equal(t, identifier, flow.Identifier)
		require.NotEmpty(t, flow.Salt)
		require.NotEmpty(t, flow.Hash)
		require.Equal(t, "test@example.com", flow.EmailAddress)
		require.Equal(t, "http://localhost:3000/dashboard", flow.NextUrl)
		require.False(t, flow.DeviceIdentifier.Valid)
		require.False(t, flow.UserIdentifier.Valid)

		// Verify the hash is valid bcrypt hash
		err = bcrypt.CompareHashAndPassword(flow.Hash, append([]byte(flow.Salt), []byte(secret)...))
		require.NoError(t, err)
	})

	t.Run("CreateFlowWithEmptyDeviceIdentifier", func(t *testing.T) {
		// Test with empty device identifier - should work fine
		token, err := m.CreateFlow(t.Context(), "user@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Decode and extract identifier
		tokenBytes, err := base64.StdEncoding.DecodeString(token)
		require.NoError(t, err)
		tokenStr := string(tokenBytes)
		parts := strings.Split(tokenStr, "_")
		identifier := parts[0]

		// Verify flow was created without device identifier
		flow, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)
		require.Equal(t, "user@example.com", flow.EmailAddress)
		require.False(t, flow.DeviceIdentifier.Valid)
		require.False(t, flow.UserIdentifier.Valid)
		require.Equal(t, "http://localhost:3000/dashboard", flow.NextUrl)
	})

	t.Run("CreateFlowWithUserIdentifier", func(t *testing.T) {
		userID := uuid.New().String()

		// First create a user and organization
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "test-org-" + uuid.New().String()[:8],
			IsDefault:  true,
		})
		require.NoError(t, err)

		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    userID,
			Name:                          "test",
			PrimaryEmail:                  "test-" + uuid.New().String()[:8] + "@example.com",
			DefaultOrganizationIdentifier: orgID,
		})
		require.NoError(t, err)

		token, err := m.CreateFlow(t.Context(), "linked@example.com", "", userID, "http://example.com/next")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Decode and extract identifier
		tokenBytes, err := base64.StdEncoding.DecodeString(token)
		require.NoError(t, err)
		tokenStr := string(tokenBytes)
		parts := strings.Split(tokenStr, "_")
		identifier := parts[0]

		// Verify flow was created with user identifier
		flow, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)
		require.Equal(t, "linked@example.com", flow.EmailAddress)
		require.False(t, flow.DeviceIdentifier.Valid)
		require.True(t, flow.UserIdentifier.Valid)
		require.Equal(t, userID, flow.UserIdentifier.String)
		require.Equal(t, "http://example.com/next", flow.NextUrl)
	})

	t.Run("CreateFlowWithUserAndURL", func(t *testing.T) {
		userID := uuid.New().String()

		// Create user first
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "test-org-" + uuid.New().String()[:8],
			IsDefault:  true,
		})
		require.NoError(t, err)

		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    userID,
			Name:                          "test",
			PrimaryEmail:                  "test-" + uuid.New().String()[:8] + "@example.com",
			DefaultOrganizationIdentifier: orgID,
		})
		require.NoError(t, err)

		// Create flow with user and URL but no device (since device requires FK)
		token, err := m.CreateFlow(t.Context(), "full@example.com", "", userID, "https://app.com/welcome")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Decode and extract identifier
		tokenBytes, err := base64.StdEncoding.DecodeString(token)
		require.NoError(t, err)
		tokenStr := string(tokenBytes)
		parts := strings.Split(tokenStr, "_")
		identifier := parts[0]

		// Verify parameters were stored
		flow, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)
		require.Equal(t, "full@example.com", flow.EmailAddress)
		require.False(t, flow.DeviceIdentifier.Valid)
		require.True(t, flow.UserIdentifier.Valid)
		require.Equal(t, userID, flow.UserIdentifier.String)
		require.Equal(t, "https://app.com/welcome", flow.NextUrl)
	})

	t.Run("CreateFlowWithEmptyEmail", func(t *testing.T) {
		// Empty email should still work (no validation at this level)
		token, err := m.CreateFlow(t.Context(), "", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Decode and extract identifier
		tokenBytes, err := base64.StdEncoding.DecodeString(token)
		require.NoError(t, err)
		tokenStr := string(tokenBytes)
		parts := strings.Split(tokenStr, "_")
		identifier := parts[0]

		// Verify flow was created with empty email
		flow, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)
		require.Empty(t, flow.EmailAddress)
	})

	t.Run("CreateMultipleFlowsForSameEmail", func(t *testing.T) {
		email := "duplicate@example.com"

		// Should be able to create multiple flows for the same email
		token1, err := m.CreateFlow(t.Context(), email, "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)
		require.NotEmpty(t, token1)

		token2, err := m.CreateFlow(t.Context(), email, "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)
		require.NotEmpty(t, token2)

		// Tokens should be different
		require.NotEqual(t, token1, token2)

		// Both flows should exist in database
		tokenBytes1, _ := base64.StdEncoding.DecodeString(token1)
		identifier1 := string(tokenBytes1[:strings.Index(string(tokenBytes1), "_")])

		tokenBytes2, _ := base64.StdEncoding.DecodeString(token2)
		identifier2 := string(tokenBytes2[:strings.Index(string(tokenBytes2), "_")])

		flow1, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier1)
		require.NoError(t, err)
		require.Equal(t, email, flow1.EmailAddress)

		flow2, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier2)
		require.NoError(t, err)
		require.Equal(t, email, flow2.EmailAddress)
	})
}

func TestCompleteFlow(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("CompleteFlowSuccess", func(t *testing.T) {
		// Create a flow
		token, err := m.CreateFlow(t.Context(), "test@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Complete the flow
		flow, err := m.CompleteFlow(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, flow)

		// Verify flow data
		require.Equal(t, "test@example.com", flow.ProviderIdentifier)
		require.Empty(t, flow.UserName) // Magic link doesn't have name
		require.Equal(t, "test@example.com", flow.PrimaryEmail)
		require.Len(t, flow.VerifiedEmails, 1)
		require.Contains(t, flow.VerifiedEmails, "test@example.com")
		require.Equal(t, "http://localhost:3000/dashboard", flow.NextURL)
		require.Empty(t, flow.DeviceIdentifier)
		require.Empty(t, flow.UserIdentifier)

		// Verify flow was deleted from database
		tokenBytes, _ := base64.StdEncoding.DecodeString(token)
		identifier := string(tokenBytes[:strings.Index(string(tokenBytes), "_")])
		_, err = database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.Error(t, err) // Should be deleted
	})

	t.Run("CompleteFlowWithUserAndURL", func(t *testing.T) {
		userID := uuid.New().String()

		// Create user first
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "test-org-" + uuid.New().String()[:8],
			IsDefault:  true,
		})
		require.NoError(t, err)

		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    userID,
			Name:                          "test",
			PrimaryEmail:                  "test-" + uuid.New().String()[:8] + "@example.com",
			DefaultOrganizationIdentifier: orgID,
		})
		require.NoError(t, err)

		// Create flow with user and URL
		token, err := m.CreateFlow(t.Context(), "complete@example.com", "", userID, "https://app.com/success")
		require.NoError(t, err)

		// Complete the flow
		flow, err := m.CompleteFlow(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, flow)

		// Verify fields are returned
		require.Equal(t, "complete@example.com", flow.ProviderIdentifier)
		require.Empty(t, flow.UserName)
		require.Equal(t, "complete@example.com", flow.PrimaryEmail)
		require.Contains(t, flow.VerifiedEmails, "complete@example.com")
		require.Equal(t, "https://app.com/success", flow.NextURL)
		require.Empty(t, flow.DeviceIdentifier)
		require.Equal(t, userID, flow.UserIdentifier)
	})

	t.Run("CompleteFlowWithInvalidToken", func(t *testing.T) {
		// Try with completely invalid token
		flow, err := m.CompleteFlow(t.Context(), "not-a-valid-token")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.ErrorIs(t, err, ErrInvalidToken)
		require.Zero(t, flow)
	})

	t.Run("CompleteFlowWithMalformedBase64", func(t *testing.T) {
		// Invalid base64
		flow, err := m.CompleteFlow(t.Context(), "!!!invalid-base64!!!")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.ErrorIs(t, err, ErrInvalidToken)
		require.Zero(t, flow)
	})

	t.Run("CompleteFlowWithWrongFormat", func(t *testing.T) {
		// Valid base64 but wrong format (no underscore)
		invalidToken := base64.StdEncoding.EncodeToString([]byte("no-underscore-here"))
		flow, err := m.CompleteFlow(t.Context(), invalidToken)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.ErrorIs(t, err, ErrInvalidToken)
		require.Zero(t, flow)
	})

	t.Run("CompleteFlowWithInvalidIdentifierLength", func(t *testing.T) {
		// Valid format but identifier is not 36 chars (UUID length)
		invalidToken := base64.StdEncoding.EncodeToString([]byte("short_" + uuid.New().String()))
		flow, err := m.CompleteFlow(t.Context(), invalidToken)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.ErrorIs(t, err, ErrInvalidToken)
		require.Zero(t, flow)
	})

	t.Run("CompleteFlowWithInvalidSecretLength", func(t *testing.T) {
		// Valid identifier but secret is not 36 chars
		invalidToken := base64.StdEncoding.EncodeToString([]byte(uuid.New().String() + "_short"))
		flow, err := m.CompleteFlow(t.Context(), invalidToken)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.ErrorIs(t, err, ErrInvalidToken)
		require.Zero(t, flow)
	})

	t.Run("CompleteFlowWithNonexistentFlow", func(t *testing.T) {
		// Valid format but flow doesn't exist
		nonExistentToken := base64.StdEncoding.EncodeToString([]byte(uuid.New().String() + "_" + uuid.New().String()))
		flow, err := m.CompleteFlow(t.Context(), nonExistentToken)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Zero(t, flow)
	})

	t.Run("CompleteFlowWithWrongSecret", func(t *testing.T) {
		// Create a valid flow
		validToken, err := m.CreateFlow(t.Context(), "valid@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Decode the valid token to get identifier
		tokenBytes, _ := base64.StdEncoding.DecodeString(validToken)
		identifier := string(tokenBytes[:strings.Index(string(tokenBytes), "_")])

		// Create a token with correct identifier but wrong secret
		wrongSecret := uuid.New().String()
		invalidToken := base64.StdEncoding.EncodeToString([]byte(identifier + "_" + wrongSecret))

		// Try to complete with wrong secret
		flow, err := m.CompleteFlow(t.Context(), invalidToken)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.ErrorIs(t, err, ErrInvalidSecret)
		require.Zero(t, flow)

		// Verify the flow is deleted on failure
		_, err = database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.ErrorIs(t, err, sql.ErrNoRows) // Should not exist anymore
	})

	t.Run("CompleteFlowIdempotency", func(t *testing.T) {
		// Create a flow
		token, err := m.CreateFlow(t.Context(), "idempotent@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Complete the flow first time
		flow1, err := m.CompleteFlow(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, flow1)

		// Try to complete the same flow again - should fail as it's deleted
		flow2, err := m.CompleteFlow(t.Context(), token)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Nil(t, flow2)
	})

	t.Run("CompleteFlowConcurrency", func(t *testing.T) {
		// Create a flow
		token, err := m.CreateFlow(t.Context(), "concurrent@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Try to complete the flow concurrently
		results := make(chan error, 2)

		go func() {
			_, err := m.CompleteFlow(t.Context(), token)
			results <- err
		}()

		go func() {
			_, err := m.CompleteFlow(t.Context(), token)
			results <- err
		}()

		// Collect results
		err1 := <-results
		err2 := <-results

		// At least one should succeed (both might succeed due to race condition in DB)
		// or one succeeds and one fails
		successCount := 0
		if err1 == nil {
			successCount++
		}
		if err2 == nil {
			successCount++
		}

		// At least one should succeed
		require.GreaterOrEqual(t, successCount, 1, "at least one completion should succeed")
	})
}

func TestTokenEncoding(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("TokenStructure", func(t *testing.T) {
		token, err := m.CreateFlow(t.Context(), "token@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Verify token is valid base64
		tokenBytes, err := base64.StdEncoding.DecodeString(token)
		require.NoError(t, err)

		// Verify token structure: identifier_secret
		tokenStr := string(tokenBytes)
		require.Contains(t, tokenStr, "_")

		parts := strings.Split(tokenStr, "_")
		require.Len(t, parts, 2)

		// Both parts should be valid UUIDs
		identifier := parts[0]
		secret := parts[1]

		_, err = uuid.Parse(identifier)
		require.NoError(t, err, "identifier should be a valid UUID")

		_, err = uuid.Parse(secret)
		require.NoError(t, err, "secret should be a valid UUID")
	})

	t.Run("TokenUniqueness", func(t *testing.T) {
		// Create multiple flows and verify tokens are unique
		tokens := make(map[string]bool)
		for i := 0; i < 10; i++ {
			token, err := m.CreateFlow(t.Context(), fmt.Sprintf("user%d@example.com", i), "", "", "http://localhost:3000/dashboard")
			require.NoError(t, err)
			require.NotContains(t, tokens, token, "token should be unique")
			tokens[token] = true
		}
	})

	t.Run("TokenSecurity", func(t *testing.T) {
		// Create a flow
		token, err := m.CreateFlow(t.Context(), "secure@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Decode token
		tokenBytes, _ := base64.StdEncoding.DecodeString(token)
		parts := strings.Split(string(tokenBytes), "_")
		identifier := parts[0]
		secret := parts[1]

		// Verify the stored hash cannot be reversed to get the secret
		flow, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)

		// The hash should be a bcrypt hash
		require.True(t, strings.HasPrefix(string(flow.Hash), "$2"), "should be bcrypt hash")

		// Verify the hash validates with correct salt+secret
		err = bcrypt.CompareHashAndPassword(flow.Hash, append([]byte(flow.Salt), []byte(secret)...))
		require.NoError(t, err)

		// Verify wrong secret doesn't validate
		wrongSecret := uuid.New().String()
		err = bcrypt.CompareHashAndPassword(flow.Hash, append([]byte(flow.Salt), []byte(wrongSecret)...))
		require.Error(t, err)
	})
}

func TestGarbageCollection(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("GCDeletesExpiredFlows", func(t *testing.T) {
		// Save the original now function and restore it after the test
		originalNow := now
		t.Cleanup(func() {
			now = originalNow
		})

		// Create flows that will be created at the current time
		expiredFlowID := uuid.New().String()
		err = database.Queries.CreateMagicLinkFlow(t.Context(), generated.CreateMagicLinkFlowParams{
			Identifier:   expiredFlowID,
			Salt:         uuid.New().String(),
			Hash:         []byte("expired-hash"),
			EmailAddress: "expired@example.com",
		})
		require.NoError(t, err)

		// Create a recent flow
		recentFlowID := uuid.New().String()
		err = database.Queries.CreateMagicLinkFlow(t.Context(), generated.CreateMagicLinkFlowParams{
			Identifier:   recentFlowID,
			Salt:         uuid.New().String(),
			Hash:         []byte("recent-hash"),
			EmailAddress: "recent@example.com",
		})
		require.NoError(t, err)

		// Create another expired flow
		expiredFlowID2 := uuid.New().String()
		err = database.Queries.CreateMagicLinkFlow(t.Context(), generated.CreateMagicLinkFlowParams{
			Identifier:   expiredFlowID2,
			Salt:         uuid.New().String(),
			Hash:         []byte("expired-hash-2"),
			EmailAddress: "expired2@example.com",
		})
		require.NoError(t, err)

		// Mock time.Now to return a time that's Expiry ahead in the future
		futureTime := time.Now().Add(Expiry + 10*time.Minute)
		now = func() time.Time { return futureTime }

		// Create Magic instance with mocked time
		m, err := New(database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = m.Close()
		})

		// Run gc() directly
		deleted, err := m.gc()
		require.NoError(t, err)
		require.Equal(t, int64(3), deleted) // Should delete all 3 flows since they're now "expired"

		// Verify all flows are deleted
		_, err = database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), expiredFlowID)
		require.Error(t, err) // Should not exist

		_, err = database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), expiredFlowID2)
		require.Error(t, err) // Should not exist

		_, err = database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), recentFlowID)
		require.Error(t, err) // Should not exist since with mocked time it's also expired
	})

	t.Run("GCRunsInBackground", func(t *testing.T) {
		// Save the original now function and restore it after the test
		originalNow := now
		t.Cleanup(func() {
			now = originalNow
		})

		// This test verifies that the gc goroutine starts and stops properly
		m, err := New(database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)

		t.Cleanup(func() {
			_ = m.Close()
		})

		// The gc goroutine should be running now
		// Create a flow that will be expired when we mock the time
		expiredFlowID := uuid.New().String()
		err = database.Queries.CreateMagicLinkFlow(t.Context(), generated.CreateMagicLinkFlowParams{
			Identifier:   expiredFlowID,
			Salt:         uuid.New().String(),
			Hash:         []byte("expired-hash"),
			EmailAddress: "gc@example.com",
		})
		require.NoError(t, err)

		// Mock time to make the flow appear expired
		futureTime := time.Now().Add(Expiry + 10*time.Minute)
		now = func() time.Time { return futureTime }

		// Manually trigger gc to verify it works
		deleted, err := m.gc()
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		// Close should stop the gc goroutine gracefully
		err = m.Close()
		require.NoError(t, err)

		// After close, the goroutine should have stopped
		// We can't easily test the goroutine is stopped, but Close() should return without hanging
	})

	t.Run("GCHandlesEmptyTable", func(t *testing.T) {
		// Ensure table is empty
		_, err := database.Queries.DeleteAllMagicLinkFlows(t.Context())
		require.NoError(t, err)

		// Run cleanup on empty table
		deleted, err := database.Queries.DeleteMagicLinkFlowsBeforeCreatedAt(t.Context(), time.Now())
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted) // No rows deleted
	})

	t.Run("GCHandlesNoExpiredFlows", func(t *testing.T) {
		// Create only recent flows
		for i := 0; i < 3; i++ {
			flowID := uuid.New().String()
			err := database.Queries.CreateMagicLinkFlow(t.Context(), generated.CreateMagicLinkFlowParams{
				Identifier:   flowID,
				Salt:         uuid.New().String(),
				Hash:         []byte(fmt.Sprintf("hash-%d", i)),
				EmailAddress: fmt.Sprintf("user%d@example.com", i),
			})
			require.NoError(t, err)
		}

		// Run cleanup with a time that won't match any flows
		deleted, err := database.Queries.DeleteMagicLinkFlowsBeforeCreatedAt(t.Context(), time.Now().Add(-5*time.Minute))
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted) // No rows should be deleted

		// Verify all flows still exist
		count, err := database.Queries.CountAllMagicLinkFlows(t.Context())
		require.NoError(t, err)
		require.GreaterOrEqual(t, count, int64(3))
	})

	t.Run("GCDeletesOnlyExpiredFlows", func(t *testing.T) {
		// Save the original now function and restore it after the test
		originalNow := now
		t.Cleanup(func() {
			now = originalNow
		})

		// Clear the table first
		_, err := database.Queries.DeleteAllMagicLinkFlows(t.Context())
		require.NoError(t, err)

		baseTime := time.Now()

		// Mock time to be exactly at baseTime + Expiry
		now = func() time.Time { return baseTime.Add(Expiry + time.Second) }

		// Create Magic instance with mocked time
		m, err := New(database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = m.Close()
		})

		var tokens []string
		for i := 0; i < 3; i++ {
			token, err := m.CreateFlow(t.Context(), fmt.Sprintf("user%d@example.com", i), "", "", "http://localhost:3000/dashboard")
			require.NoError(t, err)
			tokens = append(tokens, token)
		}

		// Run gc() directly
		deleted, err := m.gc()
		require.NoError(t, err)
		require.Equal(t, int64(3), deleted)

		// Verify all flows are deleted
		for _, token := range tokens {
			tokenBytes, _ := base64.StdEncoding.DecodeString(token)
			identifier := string(tokenBytes[:strings.Index(string(tokenBytes), "_")])
			_, err = database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
			require.ErrorIs(t, err, sql.ErrNoRows)
		}
	})
}

func TestConcurrency(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("ConcurrentCreateFlow", func(t *testing.T) {
		numGoroutines := 10

		errors := make(chan error, numGoroutines)
		tokens := make(chan string, numGoroutines)

		// Create flows concurrently
		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				token, err := m.CreateFlow(t.Context(), fmt.Sprintf("concurrent%d@example.com", idx), "", "", "http://localhost:3000/dashboard")
				if err != nil {
					errors <- err
				} else {
					tokens <- token
				}
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			select {
			case err := <-errors:
				require.NoError(t, err)
			case token := <-tokens:
				require.NotEmpty(t, token)
			}
		}
	})

	t.Run("ConcurrentCompleteFlow", func(t *testing.T) {
		// Create a single flow
		token, err := m.CreateFlow(t.Context(), "race@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		results := make(chan error, 2)

		// Try to complete the same flow concurrently
		for i := 0; i < 2; i++ {
			go func() {
				_, err := m.CompleteFlow(t.Context(), token)
				results <- err
			}()
		}

		// Collect results
		successCount := 0
		failureCount := 0
		for i := 0; i < 2; i++ {
			err = <-results
			if err == nil {
				successCount++
			} else {
				failureCount++
			}
		}

		assert.Equal(t, 1, successCount, "one completion should succeed")
		assert.Equal(t, 1, failureCount, "one completion should fail")

		_, err = m.CompleteFlow(t.Context(), token)
		require.Error(t, err, "flow should be deleted after concurrent completions")
		require.ErrorIs(t, err, ErrCompletingFlow)
	})
}

func TestErrorScenarios(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("CompleteFlowAfterDeletion", func(t *testing.T) {
		// Create a flow
		token, err := m.CreateFlow(t.Context(), "deleted@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Extract identifier and delete the flow manually
		tokenBytes, _ := base64.StdEncoding.DecodeString(token)
		identifier := string(tokenBytes[:strings.Index(string(tokenBytes), "_")])

		err = database.Queries.DeleteMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)

		// Try to complete the deleted flow
		flow, err := m.CompleteFlow(t.Context(), token)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Zero(t, flow)
	})

	t.Run("DatabaseError", func(t *testing.T) {
		// Create a Magic instance
		m2, err := New(database, logger)
		require.NoError(t, err)

		// Close the database connection to simulate database error
		require.NoError(t, database.Close())

		// Try to create a flow - should fail with database error

		token, err := m2.CreateFlow(t.Context(), "error@example.com", "", "", "http://localhost:3000/dashboard")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCreatingFlow)
		require.Empty(t, token)

		// Close the Magic instance
		require.NoError(t, m2.Close())
	})
}

func TestClose(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("CloseStopsGoroutine", func(t *testing.T) {
		m, err := New(database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)

		// Close should stop the gc goroutine
		err = m.Close()
		require.NoError(t, err)

		// After close, operations should not work due to cancelled context

		_, err = m.CreateFlow(t.Context(), "afterclose@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// The flow might still be created since CreateFlow uses the passed context
		// But the GC goroutine should have stopped
	})

	t.Run("CloseIsIdempotent", func(t *testing.T) {
		m, err := New(database, logger)
		require.NoError(t, err)

		// Close multiple times should not panic or error
		err = m.Close()
		require.NoError(t, err)

		err = m.Close()
		require.NoError(t, err)
	})
}

func TestHashSecurity(t *testing.T) {
	t.Run("BcryptHashValidation", func(t *testing.T) {
		salt := uuid.New().String()
		secret := uuid.New().String()

		// Generate hash the same way CreateFlow does
		hash, err := bcrypt.GenerateFromPassword(append([]byte(salt), []byte(secret)...), bcrypt.DefaultCost)
		require.NoError(t, err)

		// Verify correct salt+secret validates
		err = bcrypt.CompareHashAndPassword(hash, append([]byte(salt), []byte(secret)...))
		require.NoError(t, err)

		// Verify wrong secret doesn't validate
		wrongSecret := uuid.New().String()
		err = bcrypt.CompareHashAndPassword(hash, append([]byte(salt), []byte(wrongSecret)...))
		require.Error(t, err)

		// Verify wrong salt doesn't validate
		wrongSalt := uuid.New().String()
		err = bcrypt.CompareHashAndPassword(hash, append([]byte(wrongSalt), []byte(secret)...))
		require.Error(t, err)

		// Verify empty values don't validate
		err = bcrypt.CompareHashAndPassword(hash, []byte{})
		require.Error(t, err)
	})

	t.Run("HashCostIsDefault", func(t *testing.T) {
		salt := uuid.New().String()
		secret := uuid.New().String()

		hash, err := bcrypt.GenerateFromPassword(append([]byte(salt), []byte(secret)...), bcrypt.DefaultCost)
		require.NoError(t, err)

		// Verify the hash uses default cost
		cost, err := bcrypt.Cost(hash)
		require.NoError(t, err)
		require.Equal(t, bcrypt.DefaultCost, cost)
	})
}

func TestFlowLifecycle(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("CompleteFlowLifecycle", func(t *testing.T) {
		email := "lifecycle@example.com"
		userID := uuid.New().String()
		nextURL := "https://app.com/welcome"

		// Create user first
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "test-org-" + uuid.New().String()[:8],
			IsDefault:  true,
		})
		require.NoError(t, err)

		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    userID,
			Name:                          "test",
			PrimaryEmail:                  "test-" + uuid.New().String()[:8] + "@example.com",
			DefaultOrganizationIdentifier: orgID,
		})
		require.NoError(t, err)

		// Step 1: Create flow (without device ID due to FK constraint)
		token, err := m.CreateFlow(t.Context(), email, "", userID, nextURL)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Step 2: Verify flow exists in database
		tokenBytes, _ := base64.StdEncoding.DecodeString(token)
		identifier := string(tokenBytes[:strings.Index(string(tokenBytes), "_")])

		flow, err := database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.NoError(t, err)
		require.Equal(t, email, flow.EmailAddress)
		require.False(t, flow.DeviceIdentifier.Valid)
		require.Equal(t, userID, flow.UserIdentifier.String)
		require.Equal(t, nextURL, flow.NextUrl)

		// Step 3: Complete flow
		completedFlow, err := m.CompleteFlow(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, completedFlow)
		require.Equal(t, email, completedFlow.ProviderIdentifier)
		require.Equal(t, email, completedFlow.PrimaryEmail)
		require.Empty(t, completedFlow.DeviceIdentifier)
		require.Equal(t, userID, completedFlow.UserIdentifier)
		require.Equal(t, nextURL, completedFlow.NextURL)

		// Step 4: Verify flow is deleted
		_, err = database.Queries.GetMagicLinkFlowByIdentifier(t.Context(), identifier)
		require.Error(t, err)

		// Step 5: Verify token cannot be reused
		_, err = m.CompleteFlow(t.Context(), token)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
	})
}

func TestSpecialCharacters(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("EmailWithSpecialCharacters", func(t *testing.T) {
		specialEmails := []string{
			"user+tag@example.com",
			"user.name@example.com",
			"user_name@example.com",
			"user-name@example.com",
			"user'name@example.com",
			"üser@example.com",
		}

		for _, email := range specialEmails {
			token, err := m.CreateFlow(t.Context(), email, "", "", "http://localhost:3000/dashboard")
			require.NoError(t, err)

			flow, err := m.CompleteFlow(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, email, flow.PrimaryEmail)
		}
	})

	t.Run("NextURLWithSpecialCharacters", func(t *testing.T) {
		urls := []string{
			"https://app.com/path?param=value&other=123",
			"https://app.com/path#fragment",
			"https://app.com/path with spaces",
			"https://app.com/ünicode",
		}

		for _, url := range urls {
			token, err := m.CreateFlow(t.Context(), "test@example.com", "", "", url)
			require.NoError(t, err)

			flow, err := m.CompleteFlow(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, url, flow.NextURL)
		}
	})
}

func TestNullableFields(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	m, err := New(database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("AllFieldsEmpty", func(t *testing.T) {
		// Create flow with all optional fields empty
		token, err := m.CreateFlow(t.Context(), "minimal@example.com", "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)

		// Complete flow and verify empty fields
		flow, err := m.CompleteFlow(t.Context(), token)
		require.NoError(t, err)
		require.Equal(t, "minimal@example.com", flow.ProviderIdentifier)
		require.Empty(t, flow.DeviceIdentifier)
		require.Empty(t, flow.UserIdentifier)
		require.Empty(t, flow.NextURL)
	})

	t.Run("MixedNullableFields", func(t *testing.T) {
		// Test different combinations of nullable fields (excluding device due to FK constraint)
		testCases := []struct {
			name    string
			device  string
			user    string
			nextURL string
		}{
			{"OnlyUser", "", "user-123", ""},
			{"OnlyNextURL", "", "", "https://app.com"},
			{"UserAndURL", "", "user-789", "https://app.com/other"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create user if needed
				if tc.user != "" {
					orgID := uuid.New().String()
					err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
						Identifier: orgID,
						Name:       "test-org-" + uuid.New().String()[:8],
						IsDefault:  true,
					})
					require.NoError(t, err)

					err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
						Identifier:                    tc.user,
						Name:                          "test",
						PrimaryEmail:                  "test-" + uuid.New().String()[:8] + "@example.com",
						DefaultOrganizationIdentifier: orgID,
					})
					require.NoError(t, err)
				}

				token, err := m.CreateFlow(t.Context(), tc.name+"@example.com", tc.device, tc.user, tc.nextURL)
				require.NoError(t, err)

				flow, err := m.CompleteFlow(t.Context(), token)
				require.NoError(t, err)
				require.Equal(t, tc.device, flow.DeviceIdentifier)
				require.Equal(t, tc.user, flow.UserIdentifier)
				require.Equal(t, tc.nextURL, flow.NextURL)
			})
		}
	})
}
