//SPDX-License-Identifier: Apache-2.0

package manager

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/testutils"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/role"
)

func TestNew(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("BasicManager", func(t *testing.T) {
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})
		require.Nil(t, m.Github())
		require.Nil(t, m.Google())
		require.Nil(t, m.Magic())
	})

	t.Run("WithGithub", func(t *testing.T) {
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
			Github: GithubOptions{
				Enabled:      true,
				RedirectURL:  "http://localhost:8080/callback",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})
		require.NotNil(t, m.Github())
		require.Nil(t, m.Google())
		require.Nil(t, m.Magic())
	})

	t.Run("WithGoogle", func(t *testing.T) {
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
			Google: GoogleOptions{
				Enabled:      true,
				RedirectURL:  "http://localhost:8080/callback",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})
		require.Nil(t, m.Github())
		require.NotNil(t, m.Google())
		require.Nil(t, m.Magic())
	})

	t.Run("WithMagic", func(t *testing.T) {
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
			Magic: MagicOptions{
				Enabled: true,
			},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})
		require.Nil(t, m.Github())
		require.Nil(t, m.Google())
		require.NotNil(t, m.Magic())
	})

	t.Run("WithAllProviders", func(t *testing.T) {
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
			Github: GithubOptions{
				Enabled:      true,
				RedirectURL:  "http://localhost:8080/callback",
				ClientID:     "github-client",
				ClientSecret: "github-secret",
			},
			Google: GoogleOptions{
				Enabled:      true,
				RedirectURL:  "http://localhost:8080/callback",
				ClientID:     "google-client",
				ClientSecret: "google-secret",
			},
			Magic: MagicOptions{
				Enabled: true,
			},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, m)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})
		require.NotNil(t, m.Github())
		require.NotNil(t, m.Google())
		require.NotNil(t, m.Magic())
	})
}

func TestCreateSession(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	// Create manager with all providers enabled
	opts := Options{
		Configuration: configuration.Options{
			PollInterval:  time.Minute,
			SessionExpiry: time.Minute,
		},
		Github: GithubOptions{
			Enabled:      true,
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "github-client",
			ClientSecret: "github-secret",
		},
		Google: GoogleOptions{
			Enabled:      true,
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "google-client",
			ClientSecret: "google-secret",
		},
		Magic: MagicOptions{
			Enabled: true,
		},
	}

	m, err := New(opts, database, logger)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("NewUserWithGithubProvider", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "github-user-123",
			UserName:           "Test User",
			PrimaryEmail:       "test@example.com",
			VerifiedEmails:     []string{"test@example.com", "alt@example.com"},
			NextURL:            "https://app.com/dashboard",
			DeviceIdentifier:   "",
			UserIdentifier:     "", // Empty means new user
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify session structure
		require.NotEmpty(t, session.Identifier)
		_, err = uuid.Parse(session.Identifier)
		require.NoError(t, err, "session identifier should be a valid UUID")

		// Verify organization info
		require.NotEmpty(t, session.OrganizationInfo.Identifier)
		require.Equal(t, role.OwnerRole.String(), session.OrganizationInfo.Role)

		// Verify user info
		require.NotEmpty(t, session.UserInfo.Identifier)
		require.Equal(t, "Test User", session.UserInfo.Name) // Name is now set from flow data
		require.Equal(t, "test@example.com", session.UserInfo.Email)

		// Verify session metadata
		require.Equal(t, uint32(0), session.Generation)
		require.True(t, session.ExpiresAt.After(time.Now()))
		require.True(t, session.ExpiresAt.Before(time.Now().Add(31*time.Minute)))

		// Verify data was persisted correctly
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderGITHUB,
			ProviderIdentifier: "github-user-123",
		})
		require.NoError(t, err)
		require.Equal(t, session.UserInfo.Identifier, identity.UserIdentifier)

		var verifiedEmails []string
		err = json.Unmarshal(identity.VerifiedEmails, &verifiedEmails)
		require.NoError(t, err)
		require.Equal(t, flowData.VerifiedEmails, verifiedEmails)

		// Verify user was created
		user, err := database.Queries.GetUserByIdentifier(t.Context(), session.UserInfo.Identifier)
		require.NoError(t, err)
		require.Equal(t, "test@example.com", user.PrimaryEmail)
		require.Equal(t, "Test User", user.Name)
		require.Equal(t, session.OrganizationInfo.Identifier, user.DefaultOrganizationIdentifier)

		// Verify organization was created
		org, err := database.Queries.GetOrganizationByIdentifier(t.Context(), session.OrganizationInfo.Identifier)
		require.NoError(t, err)
		require.Equal(t, "Test User's Organization", org.Name)
		require.True(t, org.IsDefault)

		// Verify session was created
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		require.Equal(t, session.OrganizationInfo.Identifier, dbSession.OrganizationIdentifier)
		require.Equal(t, session.UserInfo.Identifier, dbSession.UserIdentifier)
		require.Equal(t, uint32(0), dbSession.LastGeneration)
	})

	t.Run("NewUserWithGoogleProvider", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "google-user-456",
			UserName:           "Google User",
			PrimaryEmail:       "google@example.com",
			VerifiedEmails:     []string{"google@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GoogleProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify identity was created with correct provider
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderGOOGLE,
			ProviderIdentifier: "google-user-456",
		})
		require.NoError(t, err)
		require.Equal(t, session.UserInfo.Identifier, identity.UserIdentifier)
	})

	t.Run("NewUserWithMagicProvider", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "magic@example.com",
			UserName:           "",
			PrimaryEmail:       "magic@example.com",
			VerifiedEmails:     []string{"magic@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify identity was created with correct provider
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderMAGIC,
			ProviderIdentifier: "magic@example.com",
		})
		require.NoError(t, err)
		require.Equal(t, session.UserInfo.Identifier, identity.UserIdentifier)

		// Verify organization name when no name is provided
		org, err := database.Queries.GetOrganizationByIdentifier(t.Context(), session.OrganizationInfo.Identifier)
		require.NoError(t, err)
		require.Contains(t, org.Name, " Organization") // Should have generated a random name
	})

	t.Run("ExistingUserNewIdentity", func(t *testing.T) {
		// First create a user with an organization
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "Existing Org",
			IsDefault:  true,
		})
		require.NoError(t, err)

		userID := uuid.New().String()
		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    userID,
			Name:                          "test",
			PrimaryEmail:                  "existing@example.com",
			DefaultOrganizationIdentifier: orgID,
		})
		require.NoError(t, err)

		// Create session with existing user ID
		flowData := flow.Data{
			ProviderIdentifier: "github-existing-789",
			UserName:           "Existing User",
			PrimaryEmail:       "existing@example.com",
			VerifiedEmails:     []string{"existing@example.com", "existing-alt@example.com"},
			UserIdentifier:     userID, // Existing user
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify the session uses the existing user and organization
		require.Equal(t, userID, session.UserInfo.Identifier)
		require.Equal(t, orgID, session.OrganizationInfo.Identifier)

		// Verify identity was created for existing user
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderGITHUB,
			ProviderIdentifier: "github-existing-789",
		})
		require.NoError(t, err)
		require.Equal(t, userID, identity.UserIdentifier)
	})

	t.Run("ExistingIdentityReturnsSession", func(t *testing.T) {
		// First create a complete user setup
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "Test Org",
			IsDefault:  true,
		})
		require.NoError(t, err)

		userID := uuid.New().String()
		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    userID,
			Name:                          "test",
			PrimaryEmail:                  "identity@example.com",
			DefaultOrganizationIdentifier: orgID,
		})
		require.NoError(t, err)

		// Create an identity
		verifiedEmails, _ := json.Marshal([]string{"identity@example.com"})
		err = database.Queries.CreateIdentity(t.Context(), generated.CreateIdentityParams{
			Provider:           generated.IdentitiesProviderGITHUB,
			ProviderIdentifier: "github-identity-999",
			UserIdentifier:     userID,
			VerifiedEmails:     verifiedEmails,
		})
		require.NoError(t, err)

		// Try to create session with same identity
		flowData := flow.Data{
			ProviderIdentifier: "github-identity-999",
			UserName:           "Should Not Matter",
			PrimaryEmail:       "identity@example.com",
			VerifiedEmails:     []string{"identity@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify it returns the existing user
		require.Equal(t, userID, session.UserInfo.Identifier)
		require.Equal(t, orgID, session.OrganizationInfo.Identifier)

		// Verify a new session was still created
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		require.Equal(t, userID, dbSession.UserIdentifier)
	})

	t.Run("NoVerifiedEmailsError", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "no-emails-user",
			UserName:           "No Emails",
			PrimaryEmail:       "test@example.com",
			VerifiedEmails:     []string{}, // Empty
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCreatingSession)
		require.ErrorIs(t, err, ErrInvalidFlowData)
		require.Zero(t, session)
	})

	t.Run("InvalidProviderError", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "invalid-provider-user",
			UserName:           "Invalid Provider",
			PrimaryEmail:       "invalid@example.com",
			VerifiedEmails:     []string{"invalid@example.com"},
		}

		// Use an invalid provider value
		session, err := m.CreateSession(t.Context(), flowData, flow.Provider(999))
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCreatingSession)
		require.ErrorIs(t, err, ErrInvalidProvider)
		require.Zero(t, session)
	})

	t.Run("MultipleVerifiedEmails", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "multi-email-user",
			UserName:           "Multi Email",
			PrimaryEmail:       "primary@example.com",
			VerifiedEmails: []string{
				"primary@example.com",
				"secondary@example.com",
				"tertiary@example.com",
			},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify all emails were stored
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderGITHUB,
			ProviderIdentifier: "multi-email-user",
		})
		require.NoError(t, err)

		var storedEmails []string
		err = json.Unmarshal(identity.VerifiedEmails, &storedEmails)
		require.NoError(t, err)
		require.Equal(t, flowData.VerifiedEmails, storedEmails)
	})

	t.Run("SessionExpiryTime", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "expiry-test-user",
			UserName:           "Expiry Test",
			PrimaryEmail:       "expiry@example.com",
			VerifiedEmails:     []string{"expiry@example.com"},
		}

		beforeCreate := time.Now()
		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		afterCreate := time.Now()

		// Session should expire after the session expiration time
		expectedExpiry := beforeCreate.Add(m.Configuration().SessionExpiry())
		require.True(t, session.ExpiresAt.After(expectedExpiry.Add(-1*time.Second)))
		require.True(t, session.ExpiresAt.Before(afterCreate.Add(m.Configuration().SessionExpiry()).Add(1*time.Second)))
	})

	t.Run("ConcurrentSessionCreation", func(t *testing.T) {
		// Test that multiple sessions can be created for the same identity
		flowData := flow.Data{
			ProviderIdentifier: "concurrent-user",
			UserName:           "Concurrent User",
			PrimaryEmail:       "concurrent@example.com",
			VerifiedEmails:     []string{"concurrent@example.com"},
		}

		// Create first session
		session1, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session1)

		// Create second session for same identity
		session2, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session2)

		// Sessions should be different
		require.NotEqual(t, session1.Identifier, session2.Identifier)

		// But should point to same user
		require.Equal(t, session1.UserInfo.Identifier, session2.UserInfo.Identifier)
		require.Equal(t, session1.OrganizationInfo.Identifier, session2.OrganizationInfo.Identifier)
	})

	t.Run("NonExistentUserIdentifier", func(t *testing.T) {
		// Try to create identity for non-existent user
		flowData := flow.Data{
			ProviderIdentifier: "nonexistent-link",
			UserName:           "NonExistent",
			PrimaryEmail:       "nonexistent@example.com",
			VerifiedEmails:     []string{"nonexistent@example.com"},
			UserIdentifier:     uuid.New().String(), // Non-existent user ID
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCreatingSession)
		require.Zero(t, session)

		// Verify no identity was created
		_, err = database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderGITHUB,
			ProviderIdentifier: "nonexistent-link",
		})
		require.Error(t, err)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("TransactionRollbackOnError", func(t *testing.T) {
		// Create a user but don't create the organization it references
		// This should cause a foreign key constraint error
		nonExistentOrgID := uuid.New().String()
		userID := uuid.New().String()

		// This will succeed temporarily within a transaction
		flowData := flow.Data{
			ProviderIdentifier: "rollback-test",
			UserName:           "Rollback Test",
			PrimaryEmail:       "rollback@example.com",
			VerifiedEmails:     []string{"rollback@example.com"},
			UserIdentifier:     userID,
		}

		// First we need to create the user with invalid org reference
		// to test transaction rollback
		tx, err := database.DB.BeginTx(t.Context(), nil)
		require.NoError(t, err)

		qtx := database.Queries.WithTx(tx)
		err = qtx.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:                    userID,
			Name:                          "test",
			PrimaryEmail:                  "rollback@example.com",
			DefaultOrganizationIdentifier: nonExistentOrgID, // This doesn't exist
		})
		// This should fail due to foreign key constraint
		require.Error(t, err)
		err = tx.Rollback()
		require.NoError(t, err)

		// Now try to create session with this user that shouldn't exist
		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.Error(t, err)
		require.Zero(t, session)
	})

	t.Run("EmptyProviderIdentifier", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "", // Empty
			UserName:           "Empty Provider",
			PrimaryEmail:       "empty-provider@example.com",
			VerifiedEmails:     []string{"empty-provider@example.com"},
		}

		// This should now fail due to validation
		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCreatingSession)
		require.ErrorIs(t, err, ErrInvalidFlowData)
		require.Zero(t, session)
	})

	t.Run("SpecialCharactersInData", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "special-!@#$%^&*()",
			UserName:           "User's \"Special\" Name",
			PrimaryEmail:       "special+tag@example.com",
			VerifiedEmails:     []string{"special+tag@example.com", "üñíçödé@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify special characters were handled correctly
		org, err := database.Queries.GetOrganizationByIdentifier(t.Context(), session.OrganizationInfo.Identifier)
		require.NoError(t, err)
		require.Equal(t, "User's \"Special\" Name's Organization", org.Name)

		// Verify emails with special characters
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderGITHUB,
			ProviderIdentifier: "special-!@#$%^&*()",
		})
		require.NoError(t, err)

		var emails []string
		err = json.Unmarshal(identity.VerifiedEmails, &emails)
		require.NoError(t, err)
		require.Equal(t, flowData.VerifiedEmails, emails)
	})

	t.Run("LongProviderIdentifier", func(t *testing.T) {
		// Test with a very long provider identifier (max is 255 chars)
		longID := ""
		for i := 0; i < 250; i++ {
			longID += "a"
		}

		flowData := flow.Data{
			ProviderIdentifier: longID,
			UserName:           "Long ID User",
			PrimaryEmail:       "longid@example.com",
			VerifiedEmails:     []string{"longid@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.GithubProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify it was stored correctly
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderGITHUB,
			ProviderIdentifier: longID,
		})
		require.NoError(t, err)
		require.Equal(t, longID, identity.ProviderIdentifier)
	})
}

func TestCreateSessionEdgeCases(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		Configuration: configuration.Options{
			PollInterval:  time.Minute,
			SessionExpiry: time.Minute,
		},
		Magic: MagicOptions{
			Enabled: true,
		},
	}

	m, err := New(opts, database, logger)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("DuplicateIdentityCreation", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "duplicate-test",
			UserName:           "Duplicate Test",
			PrimaryEmail:       "duplicate@example.com",
			VerifiedEmails:     []string{"duplicate@example.com"},
		}

		// Create first identity
		session1, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		// Try to create duplicate identity - should return existing user's session
		session2, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)
		require.NotNil(t, session2)

		// Should be the same user as the first session
		require.Equal(t, session1.UserInfo.Identifier, session2.UserInfo.Identifier)

		// Original identity should still exist and be unchanged
		identity, err := database.Queries.GetIdentityByProviderAndProviderIdentifier(t.Context(), generated.GetIdentityByProviderAndProviderIdentifierParams{
			Provider:           generated.IdentitiesProviderMAGIC,
			ProviderIdentifier: "duplicate-test",
		})
		require.NoError(t, err)
		require.Equal(t, session1.UserInfo.Identifier, identity.UserIdentifier)
	})

	t.Run("SessionGenerationStartsAtZero", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "generation-test",
			UserName:           "Generation Test",
			PrimaryEmail:       "generation@example.com",
			VerifiedEmails:     []string{"generation@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)
		require.Equal(t, uint32(0), session.Generation)

		// Verify in database
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		require.Equal(t, uint32(0), dbSession.LastGeneration)
	})

	t.Run("RoleAssignment", func(t *testing.T) {
		flowData := flow.Data{
			ProviderIdentifier: "role-test",
			UserName:           "Role Test",
			PrimaryEmail:       "role@example.com",
			VerifiedEmails:     []string{"role@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		// Verify role assignment
		require.Equal(t, role.OwnerRole.String(), session.OrganizationInfo.Role)
	})
}

// TestCreateSessionValidation tests the validation improvements in the implementation
func TestCreateSessionValidation(t *testing.T) {
	t.Run("ProviderIdentifierValidation", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		flowData := flow.Data{
			ProviderIdentifier: "",
			UserName:           "Test",
			PrimaryEmail:       "test@example.com",
			VerifiedEmails:     []string{"test@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidFlowData)
		require.Zero(t, session)
	})

	t.Run("DuplicateEmailPrevented", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create first user
		flowData1 := flow.Data{
			ProviderIdentifier: "user1",
			UserName:           "User One",
			PrimaryEmail:       "duplicate@example.com",
			VerifiedEmails:     []string{"duplicate@example.com"},
		}

		session1, err := m.CreateSession(t.Context(), flowData1, flow.MagicProvider)
		require.NoError(t, err)
		require.NotNil(t, session1)

		// Try to create second user with same email
		flowData2 := flow.Data{
			ProviderIdentifier: "user2",
			UserName:           "User Two",
			PrimaryEmail:       "duplicate@example.com",
			VerifiedEmails:     []string{"duplicate@example.com"},
		}

		session2, err := m.CreateSession(t.Context(), flowData2, flow.MagicProvider)
		require.Error(t, err) // Should fail due to UNIQUE constraint
		require.Zero(t, session2)
	})

	t.Run("UserCreatedWithName", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Minute,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		flowData := flow.Data{
			ProviderIdentifier: "user-with-name",
			UserName:           "John Doe",
			PrimaryEmail:       "john@example.com",
			VerifiedEmails:     []string{"john@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.Equal(t, "John Doe", session.UserInfo.Name)

		// Verify in database
		user, err := database.Queries.GetUserByIdentifier(t.Context(), session.UserInfo.Identifier)
		require.NoError(t, err)
		require.Equal(t, "John Doe", user.Name)
	})
}

func TestRefreshSession(t *testing.T) {
	t.Run("RefreshExtendsExpiry", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Second * 5,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session
		flowData := flow.Data{
			ProviderIdentifier: "refresh-test",
			UserName:           "Refresh Test",
			PrimaryEmail:       "refresh@example.com",
			VerifiedEmails:     []string{"refresh@example.com"},
		}
		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		originalExpiry := session.ExpiresAt
		originalGeneration := session.Generation

		// Wait a bit
		time.Sleep(time.Second * 1)

		// Refresh the session
		refreshedSession, err := m.RefreshSession(t.Context(), session)
		require.NoError(t, err)
		require.Equal(t, session.Identifier, refreshedSession.Identifier)
		require.True(t, refreshedSession.ExpiresAt.After(originalExpiry), "Expiry should be extended")
		require.Equal(t, originalGeneration, refreshedSession.Generation, "Generation should not change when only refreshing expiry")

		// Verify in database
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		// The refreshed session should have exactly the same expiry as in the database
		require.Equal(t, dbSession.ExpiresAt.Unix(), refreshedSession.ExpiresAt.Unix(),
			"RefreshSession should return the exact database expiry time")
		require.Equal(t, originalGeneration, dbSession.LastGeneration, "Generation should not change in DB")
	})

	t.Run("GenerationMismatchUpdatesSessionData", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Second * 10,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session
		flowData := flow.Data{
			ProviderIdentifier: "generation-test",
			UserName:           "Original Name",
			PrimaryEmail:       "original@example.com",
			VerifiedEmails:     []string{"original@example.com"},
		}
		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		// Simulate a generation update in the database (e.g., from another service)
		err = database.Queries.UpdateSessionLastGenerationByIdentifier(t.Context(), generated.UpdateSessionLastGenerationByIdentifierParams{
			LastGeneration: session.Generation + 1,
			Identifier:     session.Identifier,
		})
		require.NoError(t, err)

		// Update user info in database to simulate profile changes
		err = database.Queries.UpdateUserNameByIdentifier(t.Context(), generated.UpdateUserNameByIdentifierParams{
			Identifier: session.UserInfo.Identifier,
			Name:       "Updated Name",
		})
		require.NoError(t, err)

		err = database.Queries.UpdateUserPrimaryEmailByIdentifier(t.Context(), generated.UpdateUserPrimaryEmailByIdentifierParams{
			Identifier:   session.UserInfo.Identifier,
			PrimaryEmail: "updated@example.com",
		})
		require.NoError(t, err)

		// Refresh the session with old generation
		refreshedSession, err := m.RefreshSession(t.Context(), session)
		require.NoError(t, err)

		// Verify the generation was updated
		require.Equal(t, session.Generation+1, refreshedSession.Generation, "Generation should be updated")

		// Verify user info was refreshed
		require.Equal(t, "Updated Name", refreshedSession.UserInfo.Name, "User name should be updated")
		require.Equal(t, "updated@example.com", refreshedSession.UserInfo.Email, "User email should be updated")
	})

	t.Run("MonotonicExpiryGuarantee", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		// Create manager with short expiry
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Second * 1, // Very short expiry
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session
		flowData := flow.Data{
			ProviderIdentifier: "monotonic-test",
			UserName:           "Monotonic Test",
			PrimaryEmail:       "monotonic@example.com",
			VerifiedEmails:     []string{"monotonic@example.com"},
		}
		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		// Manually extend the session expiry in the database to be longer than what configuration would set
		// Truncate to match MySQL DATETIME precision
		futureExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
		err = database.Queries.UpdateSessionExpiryByIdentifier(t.Context(), generated.UpdateSessionExpiryByIdentifierParams{
			ExpiresAt:  futureExpiry,
			Identifier: session.Identifier,
		})
		require.NoError(t, err)

		// Refresh the session - it should NOT reduce the expiry time
		refreshedSession, err := m.RefreshSession(t.Context(), session)
		require.NoError(t, err)

		// Verify the expiry was NOT reduced
		require.True(t, refreshedSession.ExpiresAt.After(time.Now().Add(time.Minute*30)),
			"Expiry should not be reduced below database value")

		// Verify database still has the longer expiry
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		require.Equal(t, futureExpiry.Unix(), dbSession.ExpiresAt.Unix(),
			"Database expiry should not have been reduced")
		// The refreshed session should have the exact same expiry as the database
		require.Equal(t, dbSession.ExpiresAt.Unix(), refreshedSession.ExpiresAt.Unix(),
			"RefreshSession should return the exact database expiry time")
	})

	t.Run("CannotRefreshExpiredSession", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Millisecond * 100, // Very short expiry
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session
		flowData := flow.Data{
			ProviderIdentifier: "expired-test",
			UserName:           "Expired Test",
			PrimaryEmail:       "expired@example.com",
			VerifiedEmails:     []string{"expired@example.com"},
		}
		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		// Wait for session to expire
		time.Sleep(time.Second * 1)

		// Try to refresh the expired session
		_, err = m.RefreshSession(t.Context(), session)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrSessionIsExpired)
		require.ErrorIs(t, err, ErrRefreshingSession)
	})

	t.Run("NonExistentSessionRefreshFails", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Hour,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a fake session that doesn't exist in DB
		fakeSession := Session{
			Identifier: uuid.New().String(),
			OrganizationInfo: OrganizationInfo{
				Identifier: uuid.New().String(),
				IsDefault:  true,
				Role:       role.OwnerRole.String(),
			},
			UserInfo: UserInfo{
				Identifier: uuid.New().String(),
				Name:       "Fake User",
				Email:      "fake@example.com",
			},
			Generation: 0,
			ExpiresAt:  time.Now().Add(time.Hour),
		}

		// Try to refresh the non-existent session
		_, err = m.RefreshSession(t.Context(), fakeSession)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrRefreshingSession)
	})

	t.Run("ConcurrentRefreshHandling", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Second * 10,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session
		flowData := flow.Data{
			ProviderIdentifier: "concurrent-test",
			UserName:           "Concurrent Test",
			PrimaryEmail:       "concurrent@example.com",
			VerifiedEmails:     []string{"concurrent@example.com"},
		}
		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		// Wait a bit to ensure the refreshed expiry will be noticeably different
		time.Sleep(time.Second * 2)

		// Try to refresh the same session concurrently
		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := m.RefreshSession(t.Context(), session)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		// All refreshes should succeed due to serializable isolation
		require.GreaterOrEqual(t, successCount, 1, "At least one refresh should succeed")

		// Verify the session still exists and has been refreshed
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		require.True(t, dbSession.ExpiresAt.After(session.ExpiresAt), "Expiry should have been extended")
	})

	t.Run("RefreshWithOrganizationMembership", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Second * 10,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session
		flowData := flow.Data{
			ProviderIdentifier: "membership-test",
			UserName:           "Membership Test",
			PrimaryEmail:       "membership@example.com",
			VerifiedEmails:     []string{"membership@example.com"},
		}
		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)

		// Create a non-default organization and membership
		orgID := uuid.New().String()
		err = database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "Test Org",
			IsDefault:  false,
		})
		require.NoError(t, err)

		err = database.Queries.CreateMembership(t.Context(), generated.CreateMembershipParams{
			UserIdentifier:         session.UserInfo.Identifier,
			OrganizationIdentifier: orgID,
			Role:                   role.MemberRole.String(),
		})
		require.NoError(t, err)

		// Create session object with non-default org
		// Note: Session's organizations are immutable so we'll just test with the role update
		sessionWithOrg := Session{
			Identifier: session.Identifier,
			OrganizationInfo: OrganizationInfo{
				Identifier: orgID,
				IsDefault:  false,
				Role:       role.MemberRole.String(),
			},
			UserInfo:   session.UserInfo,
			Generation: session.Generation,
			ExpiresAt:  session.ExpiresAt,
		}

		// Update the generation to trigger user data refresh
		err = database.Queries.UpdateSessionLastGenerationByIdentifier(t.Context(), generated.UpdateSessionLastGenerationByIdentifierParams{
			LastGeneration: session.Generation + 1,
			Identifier:     session.Identifier,
		})
		require.NoError(t, err)

		// Update the membership role
		err = database.Queries.UpdateMembershipRoleByUserIdentifierAndOrganizationIdentifier(t.Context(), generated.UpdateMembershipRoleByUserIdentifierAndOrganizationIdentifierParams{
			UserIdentifier:         session.UserInfo.Identifier,
			OrganizationIdentifier: orgID,
			Role:                   role.AdminRole.String(),
		})
		require.NoError(t, err)

		// Refresh the session - should update role due to generation mismatch
		refreshedSession, err := m.RefreshSession(t.Context(), sessionWithOrg)
		require.NoError(t, err)
		require.Equal(t, role.AdminRole.String(), refreshedSession.OrganizationInfo.Role, "Role should be updated")
		require.Equal(t, session.Generation+1, refreshedSession.Generation, "Generation should be updated")
	})
}

func TestSessionGarbageCollection(t *testing.T) {
	t.Run("ExpiredSessionsAreDeleted", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})
		// Create manager with very short session expiry for testing
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Millisecond * 10, // Very short expiry for testing
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session that will expire quickly
		flowData := flow.Data{
			ProviderIdentifier: "gc-test-user",
			UserName:           "GC Test",
			PrimaryEmail:       "gc@example.com",
			VerifiedEmails:     []string{"gc@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Verify session was created
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		require.Equal(t, session.Identifier, dbSession.Identifier)

		// Wait for session to expire
		// Need to wait longer because database NOW() might be slightly different
		time.Sleep(time.Second * 1)

		// Manually trigger GC
		deleted, err := m.sessionGC()
		require.NoError(t, err)
		require.GreaterOrEqual(t, deleted, int64(1), "Expected at least 1 session to be deleted")

		// Verify session was deleted
		_, err = database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.Error(t, err)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("NonExpiredSessionsAreNotDeleted", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})
		// Create manager with longer session expiry
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Hour, // Long expiry
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create a session that won't expire soon
		flowData := flow.Data{
			ProviderIdentifier: "no-gc-test-user",
			UserName:           "No GC Test",
			PrimaryEmail:       "nogc@example.com",
			VerifiedEmails:     []string{"nogc@example.com"},
		}

		session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Manually trigger GC immediately
		deleted, err := m.sessionGC()
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted, "Expected 0 sessions to be deleted")

		// Verify session still exists
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
		require.NoError(t, err)
		require.Equal(t, session.Identifier, dbSession.Identifier)
	})

	t.Run("MultipleExpiredSessionsAreDeleted", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})
		// Create manager with very short session expiry
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Millisecond * 10,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create multiple sessions
		sessions := make([]Session, 3)
		for i := 0; i < 3; i++ {
			flowData := flow.Data{
				ProviderIdentifier: fmt.Sprintf("multi-gc-user-%d", i),
				UserName:           fmt.Sprintf("Multi GC User %d", i),
				PrimaryEmail:       fmt.Sprintf("multi%d@example.com", i),
				VerifiedEmails:     []string{fmt.Sprintf("multi%d@example.com", i)},
			}

			session, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
			require.NoError(t, err)
			sessions[i] = session
		}

		// Wait for all sessions to expire
		time.Sleep(time.Second * 1)

		// Manually trigger GC
		deleted, err := m.sessionGC()
		require.NoError(t, err)
		require.GreaterOrEqual(t, deleted, int64(3), "Expected at least 3 sessions to be deleted")

		// Verify all sessions were deleted
		for _, session := range sessions {
			_, err = database.Queries.GetSessionByIdentifier(t.Context(), session.Identifier)
			require.Error(t, err)
			require.ErrorIs(t, err, sql.ErrNoRows)
		}
	})

	t.Run("SessionRefreshPreventsGarbageCollection", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		// Create a single manager with short session expiry
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Second * 4, // 4 seconds expiry
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create two sessions
		session1FlowData := flow.Data{
			ProviderIdentifier: "refresh-test-user-1",
			UserName:           "Refresh Test User 1",
			PrimaryEmail:       "refresh1@example.com",
			VerifiedEmails:     []string{"refresh1@example.com"},
		}
		session1, err := m.CreateSession(t.Context(), session1FlowData, flow.MagicProvider)
		require.NoError(t, err)

		session2FlowData := flow.Data{
			ProviderIdentifier: "refresh-test-user-2",
			UserName:           "Refresh Test User 2",
			PrimaryEmail:       "refresh2@example.com",
			VerifiedEmails:     []string{"refresh2@example.com"},
		}
		session2, err := m.CreateSession(t.Context(), session2FlowData, flow.MagicProvider)
		require.NoError(t, err)

		// Verify both sessions exist
		_, err = database.Queries.GetSessionByIdentifier(t.Context(), session1.Identifier)
		require.NoError(t, err, "Session 1 should exist")
		_, err = database.Queries.GetSessionByIdentifier(t.Context(), session2.Identifier)
		require.NoError(t, err, "Session 2 should exist")

		// Wait for 2 second (half the expiry time)
		time.Sleep(time.Second * 2)

		// Refresh session 1 to extend its expiry
		refreshedSession1, err := m.RefreshSession(t.Context(), session1)
		require.NoError(t, err)
		require.Equal(t, session1.Identifier, refreshedSession1.Identifier)
		require.True(t, refreshedSession1.ExpiresAt.After(session1.ExpiresAt), "Refreshed session should have later expiry")

		// Wait for another 3 seconds (total 5 seconds)
		// Session 2 should now be expired, but session 1 should still be valid
		time.Sleep(time.Second * 3)

		// Run garbage collection
		deleted, err := m.sessionGC()
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted, "Expected exactly 1 session to be deleted")

		// Verify session 2 was deleted (not refreshed)
		_, err = database.Queries.GetSessionByIdentifier(t.Context(), session2.Identifier)
		require.Error(t, err)
		require.ErrorIs(t, err, sql.ErrNoRows, "Session 2 should have been garbage collected")

		// Verify session 1 still exists (was refreshed)
		dbSession, err := database.Queries.GetSessionByIdentifier(t.Context(), refreshedSession1.Identifier)
		require.NoError(t, err, "Session 1 should still exist after refresh")
		require.Equal(t, refreshedSession1.Identifier, dbSession.Identifier)
	})

	t.Run("GCWithNoExpiredSessions", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})
		// Create manager with normal session expiry
		opts := Options{
			Configuration: configuration.Options{
				PollInterval:  time.Minute,
				SessionExpiry: time.Hour,
			},
			Magic: MagicOptions{Enabled: true},
		}
		m, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, m.Close())
		})

		// Create multiple sessions that won't expire
		for i := 0; i < 3; i++ {
			flowData := flow.Data{
				ProviderIdentifier: fmt.Sprintf("no-expire-user-%d", i),
				UserName:           fmt.Sprintf("No Expire User %d", i),
				PrimaryEmail:       fmt.Sprintf("noexpire%d@example.com", i),
				VerifiedEmails:     []string{fmt.Sprintf("noexpire%d@example.com", i)},
			}

			_, err := m.CreateSession(t.Context(), flowData, flow.MagicProvider)
			require.NoError(t, err)
		}

		// Trigger GC immediately
		deleted, err := m.sessionGC()
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted, "Expected no sessions to be deleted")
	})
}
