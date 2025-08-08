//SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/testutils"
	"github.com/loopholelabs/auth/pkg/manager"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
	"github.com/loopholelabs/auth/pkg/manager/flow"
)

// Helper function to create a test session in the database
func createTestSession(t *testing.T, ctx context.Context, database *db.DB, expiresAt time.Time) string {
	// Create a test user and organization first
	userID := uuid.New().String()
	orgID := uuid.New().String()
	sessionID := uuid.New().String()

	err := database.Queries.CreateOrganization(ctx, generated.CreateOrganizationParams{
		Identifier: orgID,
		Name:       "Test Org",
		IsDefault:  true,
	})
	require.NoError(t, err)

	err = database.Queries.CreateUser(ctx, generated.CreateUserParams{
		Identifier:                    userID,
		Name:                          "Test User",
		PrimaryEmail:                  userID + "@example.com", // Use unique email
		DefaultOrganizationIdentifier: orgID,
	})
	require.NoError(t, err)

	err = database.Queries.CreateSession(ctx, generated.CreateSessionParams{
		Identifier:             sessionID,
		OrganizationIdentifier: orgID,
		UserIdentifier:         userID,
		LastGeneration:         0,
		ExpiresAt:              expiresAt,
	})
	require.NoError(t, err)

	return sessionID
}

func TestValidator(t *testing.T) {
	t.Run("CreateValidator", func(t *testing.T) {
		t.Run("RequiresDB", func(t *testing.T) {
			logger := logging.Test(t, logging.Zerolog, "test")
			_, err := New(Options{}, nil, logger)
			require.ErrorIs(t, err, ErrCreatingValidator)
			require.ErrorIs(t, err, ErrDBIsRequired)
		})

		t.Run("Success", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Second * 5,
				},
			}, database, logger)
			require.NoError(t, err)
			require.NotNil(t, v)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})
		})
	})

	t.Run("SessionRevocation", func(t *testing.T) {
		t.Run("EmptyCache", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Hour, // Long poll interval to control refresh
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Check non-existent session
			sessionID := uuid.New().String()
			assert.False(t, v.IsSessionRevoked(sessionID))
		})

		t.Run("CacheRefresh", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100, // Short poll interval for test
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Add revocation to database
			sessionID := uuid.New().String()
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: sessionID,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Initially not in cache
			assert.False(t, v.IsSessionRevoked(sessionID))

			// Force refresh
			v.sessionRevocationsRefresh()

			// Now should be in cache
			assert.True(t, v.IsSessionRevoked(sessionID))
		})

		t.Run("MultipleSessions", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Add multiple revocations
			sessionID1 := uuid.New().String()
			sessionID2 := uuid.New().String()
			sessionID3 := uuid.New().String()
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)

			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: sessionID1,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: sessionID2,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Force refresh
			v.sessionRevocationsRefresh()

			// Check cache state
			assert.True(t, v.IsSessionRevoked(sessionID1))
			assert.True(t, v.IsSessionRevoked(sessionID2))
			assert.False(t, v.IsSessionRevoked(sessionID3)) // Not revoked
		})

		t.Run("ExpiredRevocation", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Second * 2, // Short expiry for test (must be >= 1 second for MySQL)
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Add revocation with short expiry
			sessionID := uuid.New().String()
			expiresAt := time.Now().Add(time.Second * 2).Truncate(time.Second)
			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: sessionID,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Force refresh to populate cache
			v.sessionRevocationsRefresh()
			assert.True(t, v.IsSessionRevoked(sessionID))

			// Wait for expiry and cache cleanup (can't avoid this wait)
			time.Sleep(time.Second * 3)

			// Should be expired and removed from cache
			assert.False(t, v.IsSessionRevoked(sessionID))
		})
	})

	t.Run("SessionRevalidation", func(t *testing.T) {
		t.Run("EmptyCache", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Hour,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Check non-existent session
			sessionID := uuid.New().String()
			assert.False(t, v.IsSessionRevalidated(sessionID, 0))
			assert.False(t, v.IsSessionRevalidated(sessionID, 10))
		})

		t.Run("GenerationComparison", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Create a session first
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
			sessionID := createTestSession(t, t.Context(), database, expiresAt)

			// Add revalidation with generation 5
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID,
				Generation:        5,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Force refresh
			v.sessionRevalidationsRefresh()

			// IsSessionRevalidated returns true if cached generation >= passed generation
			// Cached generation is 5, so:
			assert.True(t, v.IsSessionRevalidated(sessionID, 4))    // 5 >= 4, no revalidation needed
			assert.True(t, v.IsSessionRevalidated(sessionID, 5))    // 5 >= 5, no revalidation needed
			assert.False(t, v.IsSessionRevalidated(sessionID, 6))   // 5 < 6, revalidation needed
			assert.False(t, v.IsSessionRevalidated(sessionID, 100)) // 5 < 100, revalidation needed
		})

		t.Run("MultipleRevalidations", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Create sessions first
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
			sessionID1 := createTestSession(t, t.Context(), database, expiresAt)
			sessionID2 := createTestSession(t, t.Context(), database, expiresAt)
			sessionID3 := createTestSession(t, t.Context(), database, expiresAt)

			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID1,
				Generation:        3,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID2,
				Generation:        10,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID3,
				Generation:        0,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Wait for refresh
			time.Sleep(time.Millisecond * 200)

			// Test each session's generation threshold
			// sessionID1 has generation 3 cached
			assert.True(t, v.IsSessionRevalidated(sessionID1, 2))  // 3 >= 2
			assert.True(t, v.IsSessionRevalidated(sessionID1, 3))  // 3 >= 3
			assert.False(t, v.IsSessionRevalidated(sessionID1, 4)) // 3 >= 4 is false

			// sessionID2 has generation 10 cached
			assert.True(t, v.IsSessionRevalidated(sessionID2, 9))   // 10 >= 9
			assert.True(t, v.IsSessionRevalidated(sessionID2, 10))  // 10 >= 10
			assert.False(t, v.IsSessionRevalidated(sessionID2, 11)) // 10 >= 11 is false

			// sessionID3 has generation 0 cached
			assert.True(t, v.IsSessionRevalidated(sessionID3, 0))  // 0 >= 0
			assert.False(t, v.IsSessionRevalidated(sessionID3, 1)) // 0 >= 1 is false
		})

		t.Run("ExpiredRevalidation", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Second * 2, // Must be >= 1 second for MySQL
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Create a session first
			expiresAt := time.Now().Add(time.Second * 2).Truncate(time.Second)
			sessionID := createTestSession(t, t.Context(), database, expiresAt)

			// Add revalidation with short expiry
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID,
				Generation:        5,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Wait for refresh
			time.Sleep(time.Millisecond * 200)
			assert.True(t, v.IsSessionRevalidated(sessionID, 5))

			// Wait for expiry (can't avoid this wait)
			time.Sleep(time.Second * 3)

			// Should be expired and removed from cache
			assert.False(t, v.IsSessionRevalidated(sessionID, 5))
		})
	})

	t.Run("SessionRevalidationWithManager", func(t *testing.T) {
		t.Run("UpdateUserData", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			// Create manager and validator
			m, err := manager.New(manager.Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute * 30,
					PollInterval:  time.Second * 5,
				},
			}, database, logger)
			require.NoError(t, err)

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute * 30,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, m.Close())
				require.NoError(t, v.Close())
			})

			// Create a session
			flowData := flow.Data{
				UserIdentifier:     "",
				UserName:           "Test User",
				PrimaryEmail:       "test@example.com",
				ProviderIdentifier: "test-provider-id",
				VerifiedEmails:     []string{"test@example.com"},
			}
			session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
			require.NoError(t, err)

			// Initially, no revalidation needed
			assert.False(t, v.IsSessionRevalidated(session.Identifier, session.Generation))

			// Update user name (this should increment generation)
			err = database.Queries.UpdateUserNameByIdentifier(t.Context(), generated.UpdateUserNameByIdentifierParams{
				Name:       "Updated User",
				Identifier: session.UserInfo.Identifier,
			})
			require.NoError(t, err)

			// Update session generation
			err = database.Queries.UpdateSessionLastGenerationByIdentifier(t.Context(), generated.UpdateSessionLastGenerationByIdentifierParams{
				LastGeneration: session.Generation + 1,
				Identifier:     session.Identifier,
			})
			require.NoError(t, err)

			// Create revalidation entry
			expiresAt := time.Now().Add(time.Minute * 30).Truncate(time.Second)
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: session.Identifier,
				Generation:        session.Generation + 1,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Manually refresh the cache
			v.sessionRevalidationsRefresh()

			// The cached generation is session.Generation + 1
			// IsSessionRevalidated returns true if cached generation >= passed generation
			// So checking with old generation returns true (cached gen+1 >= gen)
			assert.True(t, v.IsSessionRevalidated(session.Identifier, session.Generation))
			// New generation should also be valid (cached gen+1 >= gen+1)
			assert.True(t, v.IsSessionRevalidated(session.Identifier, session.Generation+1))
		})

		t.Run("RevokedSessionCheck", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			// Create manager and validator
			m, err := manager.New(manager.Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute * 30,
					PollInterval:  time.Second * 5,
				},
			}, database, logger)
			require.NoError(t, err)

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute * 30,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, m.Close())
				require.NoError(t, v.Close())
			})

			// Create a session
			flowData := flow.Data{
				UserIdentifier:     "",
				UserName:           "Test User",
				PrimaryEmail:       "test@example.com",
				ProviderIdentifier: "test-provider-id-2",
				VerifiedEmails:     []string{"test@example.com"},
			}
			session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
			require.NoError(t, err)

			// Initially not revoked
			assert.False(t, v.IsSessionRevoked(session.Identifier))

			// Revoke the session
			err = m.RevokeSession(t.Context(), session.Identifier)
			require.NoError(t, err)

			// Manually refresh the cache
			v.sessionRevocationsRefresh()

			// Now should be revoked
			assert.True(t, v.IsSessionRevoked(session.Identifier))
		})
	})

	t.Run("CombinedCaches", func(t *testing.T) {
		t.Run("BothCachesActive", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Create sessions for different scenarios
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)

			// Revoked session (doesn't need to be in sessions table)
			revokedSession := uuid.New().String()

			// Revalidated session (needs to be in sessions table)
			revalidatedSession := createTestSession(t, t.Context(), database, expiresAt)

			// Both revoked and revalidated (needs to be in sessions table)
			bothSession := createTestSession(t, t.Context(), database, expiresAt)

			// Neither session (not in any cache)
			neitherSession := uuid.New().String()

			// Add to revocation cache
			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: revokedSession,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: bothSession,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Add to revalidation cache
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: revalidatedSession,
				Generation:        7,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: bothSession,
				Generation:        3,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Wait for refresh
			time.Sleep(time.Millisecond * 200)

			// Verify cache states
			assert.True(t, v.IsSessionRevoked(revokedSession))
			assert.False(t, v.IsSessionRevalidated(revokedSession, 1))

			assert.False(t, v.IsSessionRevoked(revalidatedSession))
			assert.True(t, v.IsSessionRevalidated(revalidatedSession, 7))

			assert.True(t, v.IsSessionRevoked(bothSession))
			assert.True(t, v.IsSessionRevalidated(bothSession, 3))

			assert.False(t, v.IsSessionRevoked(neitherSession))
			assert.False(t, v.IsSessionRevalidated(neitherSession, 1))
		})
	})

	t.Run("RefreshErrorHandling", func(t *testing.T) {
		t.Run("ContinuesAfterError", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			// Add initial data
			sessionID := uuid.New().String()
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: sessionID,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Wait for initial refresh
			time.Sleep(time.Millisecond * 200)
			assert.True(t, v.IsSessionRevoked(sessionID))

			// Close database to cause errors
			err = database.DB.Close()
			require.NoError(t, err)

			// Wait for failed refresh attempts (can't avoid this wait)
			time.Sleep(time.Millisecond * 300)

			// Cache should still have old data
			assert.True(t, v.IsSessionRevoked(sessionID))

			// Clean up validator
			v.cancel()
			v.wg.Wait()
		})
	})

	t.Run("GarbageCollection", func(t *testing.T) {
		t.Run("DatabaseCleanup", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Second * 2,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Add expired entries (past expiry)
			expiredID1 := uuid.New().String()
			expiredID2 := uuid.New().String()
			// Add active entries
			activeID := uuid.New().String()

			// Create with past expiry (will be cleaned by GC)
			_, err = database.DB.Exec(`
				INSERT INTO session_revocations (session_identifier, expires_at, created_at)
				VALUES (?, DATE_SUB(NOW(), INTERVAL 1 HOUR), CURRENT_TIMESTAMP)
			`, expiredID1)
			require.NoError(t, err)

			_, err = database.DB.Exec(`
				INSERT INTO session_revalidations (session_identifier, generation, expires_at, created_at)
				VALUES (?, 5, DATE_SUB(NOW(), INTERVAL 1 HOUR), CURRENT_TIMESTAMP)
			`, expiredID2)
			require.NoError(t, err)

			// Create active entries
			futureExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: activeID,
				ExpiresAt:         futureExpiry,
			})
			require.NoError(t, err)

			// Run garbage collection
			deleted, err := database.Queries.DeleteExpiredSessionRevocations(t.Context())
			require.NoError(t, err)
			assert.Equal(t, int64(1), deleted)

			deleted, err = database.Queries.DeleteExpiredSessionRevalidations(t.Context())
			require.NoError(t, err)
			assert.Equal(t, int64(1), deleted)

			// Verify only active entries remain
			revocations, err := database.Queries.GetAllSessionRevocations(t.Context())
			require.NoError(t, err)
			assert.Len(t, revocations, 1)
			assert.Equal(t, activeID, revocations[0].SessionIdentifier)

			revalidations, err := database.Queries.GetAllSessionRevalidations(t.Context())
			require.NoError(t, err)
			assert.Empty(t, revalidations)
		})
	})

	t.Run("Configuration", func(t *testing.T) {
		t.Run("DynamicUpdate", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			// Start with short expiry
			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Second * 2,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Verify initial configuration
			assert.Equal(t, time.Second*2, v.Configuration().SessionExpiry())

			// Update configuration in database
			err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
				ConfigurationKey:   string(configuration.SessionExpiryKey),
				ConfigurationValue: "10s",
			})
			require.NoError(t, err)

			// Wait for configuration update
			time.Sleep(time.Millisecond * 200)

			// Verify updated configuration
			assert.Equal(t, time.Second*10, v.Configuration().SessionExpiry())
		})
	})

	t.Run("EdgeCases", func(t *testing.T) {
		t.Run("ZeroGeneration", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
			sessionID := createTestSession(t, t.Context(), database, expiresAt)
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID,
				Generation:        0,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Wait for refresh
			time.Sleep(time.Millisecond * 200)

			// Generation 0 is cached
			assert.True(t, v.IsSessionRevalidated(sessionID, 0))  // 0 >= 0
			assert.False(t, v.IsSessionRevalidated(sessionID, 1)) // 0 >= 1 is false
		})

		t.Run("MaxGeneration", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
			sessionID := createTestSession(t, t.Context(), database, expiresAt)
			maxGen := ^uint32(0) - 1 // Max uint32 - 1
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID,
				Generation:        maxGen,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			// Wait for refresh
			time.Sleep(time.Millisecond * 200)

			// maxGen is cached
			assert.True(t, v.IsSessionRevalidated(sessionID, maxGen-1))  // maxGen >= maxGen-1
			assert.True(t, v.IsSessionRevalidated(sessionID, maxGen))    // maxGen >= maxGen
			assert.False(t, v.IsSessionRevalidated(sessionID, maxGen+1)) // maxGen >= maxGen+1 is false (overflow wraps to 0)
		})

		t.Run("DuplicateEntries", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 100,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			sessionID := uuid.New().String()
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)

			// Try to create duplicate revocation (should fail due to unique constraint)
			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: sessionID,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
				SessionIdentifier: sessionID,
				ExpiresAt:         expiresAt.Add(time.Hour), // Different expiry
			})
			require.Error(t, err) // Should fail due to unique constraint

			// Try to create duplicate revalidation with same generation (should fail)
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID,
				Generation:        5,
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)

			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID,
				Generation:        5, // Same generation
				ExpiresAt:         expiresAt.Add(time.Hour),
			})
			require.Error(t, err) // Should fail due to primary key constraint

			// Different generation should work
			err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
				SessionIdentifier: sessionID,
				Generation:        6, // Different generation
				ExpiresAt:         expiresAt,
			})
			require.NoError(t, err)
		})
	})

	t.Run("Concurrency", func(t *testing.T) {
		t.Run("ConcurrentAccess", func(t *testing.T) {
			container := testutils.SetupMySQLContainer(t)
			logger := logging.Test(t, logging.Zerolog, "test")
			database, err := db.New(container.URL, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, database.Close())
			})

			v, err := New(Options{
				Configuration: configuration.Options{
					SessionExpiry: time.Minute,
					PollInterval:  time.Millisecond * 50,
				},
			}, database, logger)
			require.NoError(t, err)

			t.Cleanup(func() {
				err := v.Close()
				require.NoError(t, err)
			})

			// Create test data
			sessionCount := 100
			sessions := make([]string, sessionCount)
			expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)

			for i := 0; i < sessionCount; i++ {
				// Create sessions for revalidation tests, use UUID for revocation-only
				if i%3 == 0 {
					// Will need revalidation - must be in sessions table
					sessions[i] = createTestSession(t, t.Context(), database, expiresAt)
				} else {
					// Only for revocation - doesn't need to be in sessions table
					sessions[i] = uuid.New().String()
				}

				if i%2 == 0 {
					// Even: revoked
					err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
						SessionIdentifier: sessions[i],
						ExpiresAt:         expiresAt,
					})
					require.NoError(t, err)
				}
				if i%3 == 0 {
					// Divisible by 3: revalidated (session already created above)
					err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
						SessionIdentifier: sessions[i],
						Generation:        uint32(i),
						ExpiresAt:         expiresAt,
					})
					require.NoError(t, err)
				}
			}

			// Wait for initial refresh
			time.Sleep(time.Millisecond * 100)

			// Concurrent reads
			done := make(chan bool)
			for i := 0; i < 10; i++ {
				go func() {
					for j := 0; j < 1000; j++ {
						idx := j % sessionCount
						v.IsSessionRevoked(sessions[idx])
						v.IsSessionRevalidated(sessions[idx], uint32(idx))
					}
					done <- true
				}()
			}

			// Wait for all goroutines
			for i := 0; i < 10; i++ {
				<-done
			}

			// Verify final state
			for i := 0; i < sessionCount; i++ {
				if i%2 == 0 {
					assert.True(t, v.IsSessionRevoked(sessions[i]))
				} else {
					assert.False(t, v.IsSessionRevoked(sessions[i]))
				}
				if i%3 == 0 {
					assert.True(t, v.IsSessionRevalidated(sessions[i], uint32(i)))
				} else {
					assert.False(t, v.IsSessionRevalidated(sessions[i], uint32(i)))
				}
			}
		})
	})
}

func TestValidatorIntegration(t *testing.T) {
	t.Run("SessionLifecycle", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		v, err := New(Options{
			Configuration: configuration.Options{
				SessionExpiry: time.Second * 5,
				PollInterval:  time.Millisecond * 100,
			},
		}, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := v.Close()
			require.NoError(t, err)
		})

		// Create a session first
		expiresAt := time.Now().Add(time.Second * 10).Truncate(time.Second)
		sessionID := createTestSession(t, t.Context(), database, expiresAt)

		// Phase 1: Session is active (not in any cache)
		assert.False(t, v.IsSessionRevoked(sessionID))
		assert.False(t, v.IsSessionRevalidated(sessionID, 1))

		// Phase 2: Session needs revalidation (generation 3)
		err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
			SessionIdentifier: sessionID,
			Generation:        3,
			ExpiresAt:         expiresAt,
		})
		require.NoError(t, err)

		// Wait for cache refresh
		time.Sleep(time.Millisecond * 200)

		assert.False(t, v.IsSessionRevoked(sessionID))
		assert.True(t, v.IsSessionRevalidated(sessionID, 2))  // 3 >= 2
		assert.True(t, v.IsSessionRevalidated(sessionID, 3))  // 3 >= 3
		assert.False(t, v.IsSessionRevalidated(sessionID, 4)) // 3 >= 4 is false

		// Phase 3: Session is revoked
		err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
			SessionIdentifier: sessionID,
			ExpiresAt:         expiresAt,
		})
		require.NoError(t, err)

		// Wait for cache refresh
		time.Sleep(time.Millisecond * 200)

		assert.True(t, v.IsSessionRevoked(sessionID))
		assert.True(t, v.IsSessionRevalidated(sessionID, 3)) // Still in revalidation cache

		// Phase 4: Wait for expiry (can't avoid this wait)
		time.Sleep(time.Second * 10)

		// Both caches should be cleared
		assert.False(t, v.IsSessionRevoked(sessionID))
		assert.False(t, v.IsSessionRevalidated(sessionID, 3))
	})

	t.Run("RealWorldScenario", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		// Simulate a production-like configuration
		v, err := New(Options{
			Configuration: configuration.Options{
				SessionExpiry: time.Minute * 30,
				PollInterval:  time.Second * 5,
			},
		}, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := v.Close()
			require.NoError(t, err)
		})

		// Simulate various session states
		longExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
		shortExpiry := time.Now().Add(time.Second).Truncate(time.Second)

		activeSession := createTestSession(t, t.Context(), database, longExpiry)
		revokedSession := createTestSession(t, t.Context(), database, longExpiry)
		outdatedSession := createTestSession(t, t.Context(), database, longExpiry) // Needs revalidation
		expiredSession := createTestSession(t, t.Context(), database, shortExpiry)

		// Setup revoked session
		err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
			SessionIdentifier: revokedSession,
			ExpiresAt:         longExpiry,
		})
		require.NoError(t, err)

		// Setup outdated session (needs revalidation)
		err = database.Queries.CreateSessionRevalidation(t.Context(), generated.CreateSessionRevalidationParams{
			SessionIdentifier: outdatedSession,
			Generation:        10,
			ExpiresAt:         longExpiry,
		})
		require.NoError(t, err)

		// Setup expired entries
		err = database.Queries.CreateSessionRevocation(t.Context(), generated.CreateSessionRevocationParams{
			SessionIdentifier: expiredSession,
			ExpiresAt:         shortExpiry,
		})
		require.NoError(t, err)

		// Force cache refresh
		v.sessionRevocationsRefresh()
		v.sessionRevalidationsRefresh()

		// Verify states
		assert.False(t, v.IsSessionRevoked(activeSession))
		assert.True(t, v.IsSessionRevoked(revokedSession))
		assert.False(t, v.IsSessionRevoked(outdatedSession))
		assert.True(t, v.IsSessionRevoked(expiredSession))

		assert.False(t, v.IsSessionRevalidated(activeSession, 1))
		assert.False(t, v.IsSessionRevalidated(revokedSession, 1))
		assert.True(t, v.IsSessionRevalidated(outdatedSession, 9))   // 10 >= 9
		assert.True(t, v.IsSessionRevalidated(outdatedSession, 10))  // 10 >= 10
		assert.False(t, v.IsSessionRevalidated(outdatedSession, 11)) // 10 >= 11 is false
		assert.False(t, v.IsSessionRevalidated(expiredSession, 1))

		// Wait for short expiry to pass (can't avoid this wait)
		time.Sleep(time.Second * 2)

		// Expired session should be cleared from cache
		assert.False(t, v.IsSessionRevoked(expiredSession))
	})
}
