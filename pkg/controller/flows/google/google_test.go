//SPDX-License-Identifier: Apache-2.0

package google

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/testutils"
)

// Helper function to create OAuth2 token response
func mockOAuth2TokenResponse(accessToken string) testutils.MockResponse { //nolint:unparam
	return testutils.MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "bearer",
			"expires_in":   3600,
			"scope":        "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
		},
	}
}

// Helper function to create Google user response
func mockGoogleUserResponse(id int64, name string, email string, verified bool) testutils.MockResponse { //nolint:unparam
	return testutils.MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"sub":            id,
			"name":           name,
			"email":          email,
			"email_verified": verified,
		},
	}
}

func TestNew(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("ValidOptions", func(t *testing.T) {
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, g)
		require.Equal(t, http.DefaultClient, g.httpClient)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})
	})

	t.Run("ValidOptionsWithCustomClient", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, g)
		require.Equal(t, mockClient.HTTPClient, g.httpClient)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})
	})

	t.Run("NilOptions", func(t *testing.T) {
		g, err := New(nil, database, logger)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, g)
	})

	t.Run("MissingRedirectURL", func(t *testing.T) {
		opts := &Options{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		g, err := New(opts, database, logger)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, g)
	})

	t.Run("MissingClientID", func(t *testing.T) {
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientSecret: "test-client-secret",
		}

		g, err := New(opts, database, logger)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, g)
	})

	t.Run("MissingClientSecret", func(t *testing.T) {
		opts := &Options{
			RedirectURL: "http://localhost:8080/callback",
			ClientID:    "test-client-id",
		}

		g, err := New(opts, database, logger)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, g)
	})

	t.Run("NilDatabase", func(t *testing.T) {
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		g, err := New(opts, nil, logger)
		require.ErrorIs(t, err, ErrDBIsRequired)
		require.Nil(t, g)
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

	opts := &Options{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	g, err := New(opts, database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, g.Close())
	})

	t.Run("CreateFlowSuccess", func(t *testing.T) {
		authURL, err := g.CreateFlow(t.Context(), "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)
		require.NotEmpty(t, authURL)

		// Parse the auth URL to validate it
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		require.Equal(t, "accounts.google.com", u.Host)
		require.Equal(t, "/o/oauth2/auth", u.Path)

		// Check query parameters
		q := u.Query()
		require.Equal(t, "test-client-id", q.Get("client_id"))
		require.Equal(t, "http://localhost:8080/callback", q.Get("redirect_uri"))
		require.Equal(t, "code", q.Get("response_type"))
		require.Equal(t, "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile", q.Get("scope"))
		require.NotEmpty(t, q.Get("state")) // This is the flow identifier
		require.NotEmpty(t, q.Get("code_challenge"))
		require.Equal(t, "S256", q.Get("code_challenge_method"))

		// Verify flow was created in database
		flowID := q.Get("state")
		flow, err := database.Queries.GetGoogleOAuthFlowByIdentifier(t.Context(), flowID)
		require.NoError(t, err)
		require.Equal(t, flowID, flow.Identifier)
		require.NotEmpty(t, flow.Verifier)
		require.NotEmpty(t, flow.Challenge)
		require.Equal(t, "http://localhost:3000/dashboard", flow.NextUrl.String)
		require.False(t, flow.DeviceIdentifier.Valid)
		require.False(t, flow.UserIdentifier.Valid)
	})

	t.Run("CreateFlowWithUser", func(t *testing.T) {
		userID := uuid.New().String()

		// First create a user and organization
		orgID := uuid.New().String()
		err := database.Queries.CreateOrganization(t.Context(), generated.CreateOrganizationParams{
			Identifier: orgID,
			Name:       "test-org-" + uuid.New().String()[:8], // Unique name
			IsDefault:  true,
		})
		require.NoError(t, err)

		err = database.Queries.CreateUser(t.Context(), generated.CreateUserParams{
			Identifier:          userID,
			PrimaryEmail:        "test-" + uuid.New().String()[:8] + "@example.com", // Unique email
			DefaultOrganization: orgID,
		})
		require.NoError(t, err)

		authURL, err := g.CreateFlow(t.Context(), "", userID, "http://example.com/next")
		require.NoError(t, err)
		require.NotEmpty(t, authURL)

		// Parse and get flow ID
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		flowID := u.Query().Get("state")

		// Verify flow was created with user ID
		flow, err := database.Queries.GetGoogleOAuthFlowByIdentifier(t.Context(), flowID)
		require.NoError(t, err)
		require.False(t, flow.DeviceIdentifier.Valid)
		require.True(t, flow.UserIdentifier.Valid)
		require.Equal(t, userID, flow.UserIdentifier.String)
		require.Equal(t, "http://example.com/next", flow.NextUrl.String)
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

	t.Run("CompleteFlowSuccess", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			mockGoogleUserResponse(12345, "Test User", "test@example.com", true))

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow first
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
			NextUrl: sql.NullString{
				String: "http://localhost:3000/dashboard",
				Valid:  true,
			},
		})
		require.NoError(t, err)

		// Complete the flow
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.NoError(t, err)
		require.NotNil(t, flow)

		// Verify flow data
		require.Equal(t, "12345", flow.Identifier)
		require.Equal(t, "Test User", flow.Name)
		require.Equal(t, "test@example.com", flow.PrimaryEmail)
		require.Len(t, flow.VerifiedEmails, 1)
		require.Contains(t, flow.VerifiedEmails, "test@example.com")
		require.Equal(t, "http://localhost:3000/dashboard", flow.NextURL)
		require.Empty(t, flow.DeviceIdentifier)
		require.Empty(t, flow.UserIdentifier)

		// Verify flow was deleted from database
		_, err = database.Queries.GetGoogleOAuthFlowByIdentifier(t.Context(), flowID)
		require.Error(t, err)

		// Verify HTTP requests were made
		mockClient.AssertRequestMade(t, "oauth2.googleapis.com/token")
		mockClient.AssertRequestMade(t, "www.googleapis.com/oauth2/v3/userinfo")
		mockClient.AssertNumberOfRequests(t, 2)
	})

	t.Run("CompleteFlowWithNoVerifiedEmail", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		// User with unverified email
		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			mockGoogleUserResponse(12345, "Test User", "unverified@example.com", false))

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to unverified email
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoVerifiedEmails)
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithEmptyEmail", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		// User with empty email
		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			mockGoogleUserResponse(12345, "Test User", "", true))

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to empty email
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoVerifiedEmails)
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithInvalidCode", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// OAuth2 token exchange fails
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			testutils.MockResponse{
				StatusCode: http.StatusBadRequest,
				Body: map[string]interface{}{
					"error":             "invalid_grant",
					"error_description": "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
				},
			})

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to invalid code
		flow, err := g.CompleteFlow(t.Context(), flowID, "invalid-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithGoogleAPIError", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		// Google API returns error
		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			testutils.MockResponse{
				StatusCode: http.StatusUnauthorized,
				Body:       `{"error": {"code": 401, "message": "Invalid Credentials"}}`,
			})

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to API error
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidResponse)
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithNetworkError", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		// Network error for userinfo endpoint
		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			testutils.MockResponse{
				Error: errors.New("network timeout"),
			})

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to network error
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Contains(t, err.Error(), "network timeout")
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithNonexistentFlow", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Try to complete a non-existent flow
		flow, err := g.CompleteFlow(t.Context(), "nonexistent-flow-id", "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Nil(t, flow)

		// No HTTP requests should have been made
		mockClient.AssertNumberOfRequests(t, 0)
	})

	t.Run("CompleteFlowWithInvalidJSON", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		// Invalid JSON response from userinfo endpoint
		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			testutils.MockResponse{
				StatusCode: http.StatusOK,
				Body:       "not valid json",
			})

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to invalid JSON
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)

		// Check that it's a JSON unmarshal error
		var jsonErr *json.SyntaxError
		require.True(t, errors.As(err, &jsonErr) || strings.Contains(err.Error(), "invalid character"))
		require.Nil(t, flow)
	})
}

func TestAuthURLGeneration(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := &Options{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	g, err := New(opts, database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, g.Close())
	})

	t.Run("ValidateAuthURLParameters", func(t *testing.T) {
		authURL, err := g.CreateFlow(t.Context(), "", "", "")
		require.NoError(t, err)

		// Parse URL and validate OAuth2 parameters
		u, err := url.Parse(authURL)
		require.NoError(t, err)

		// Validate base URL
		require.Equal(t, "https", u.Scheme)
		require.Equal(t, "accounts.google.com", u.Host)
		require.Equal(t, "/o/oauth2/auth", u.Path)

		// Validate query parameters
		q := u.Query()

		// Standard OAuth2 parameters
		require.Equal(t, "test-client-id", q.Get("client_id"))
		require.Equal(t, "http://localhost:8080/callback", q.Get("redirect_uri"))
		require.Equal(t, "code", q.Get("response_type"))
		require.Equal(t, "online", q.Get("access_type"))
		require.Equal(t, "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile", q.Get("scope"))

		// PKCE parameters
		require.NotEmpty(t, q.Get("code_challenge"))
		require.Equal(t, "S256", q.Get("code_challenge_method"))

		// State parameter (flow ID)
		require.NotEmpty(t, q.Get("state"))

		// Validate state is a valid UUID
		flowID := q.Get("state")
		_, err = uuid.Parse(flowID)
		require.NoError(t, err)
	})
}

func TestOAuth2Integration(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("OAuth2ConfigSetup", func(t *testing.T) {
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Validate OAuth2 config
		require.NotNil(t, g.config)
		require.Equal(t, "test-client-id", g.config.ClientID)
		require.Equal(t, "test-client-secret", g.config.ClientSecret)
		require.Equal(t, "http://localhost:8080/callback", g.config.RedirectURL)
		require.Equal(t, []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}, g.config.Scopes)

		// Validate Google endpoints
		require.Equal(t, "https://accounts.google.com/o/oauth2/auth", g.config.Endpoint.AuthURL)
		require.Equal(t, "https://oauth2.googleapis.com/token", g.config.Endpoint.TokenURL)
	})

	t.Run("CustomHTTPClientPropagation", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Mock the token exchange to verify custom client is used
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		// Mock Google API responses
		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			mockGoogleUserResponse(12345, "Test User", "test@example.com", true))

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create and complete a flow to verify custom client is used

		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete flow - this should use the custom HTTP client
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.NoError(t, err)
		require.NotNil(t, flow)

		// Verify all requests were made through the custom client
		requests := mockClient.GetRequests()
		require.Len(t, requests, 2)

		// Check request order and URLs
		require.Contains(t, requests[0].URL, "oauth2.googleapis.com/token")
		require.Contains(t, requests[1].URL, "www.googleapis.com/oauth2/v3/userinfo")

		// Verify authorization header was set correctly
		require.Equal(t, "token test-access-token", requests[1].Headers.Get("Authorization"))
	})
}

func TestErrorHandling(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	t.Run("TokenExchangeError", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Mock OAuth2 error response
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			testutils.MockResponse{
				StatusCode: http.StatusBadRequest,
				Body: map[string]interface{}{
					"error":             "invalid_grant",
					"error_description": "The provided authorization grant is invalid",
				},
			})

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Try to complete flow
		flow, err := g.CompleteFlow(t.Context(), flowID, "invalid-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)

		// oauth2 package wraps the error
		var oauth2Err *oauth2.RetrieveError
		require.ErrorAs(t, err, &oauth2Err)
		require.Nil(t, flow)
	})

	t.Run("GoogleAPIRateLimitError", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://oauth2.googleapis.com/token",
			mockOAuth2TokenResponse("test-access-token"))

		// Google API rate limit error
		mockClient.SetResponse("https://www.googleapis.com/oauth2/v3/userinfo",
			testutils.MockResponse{
				StatusCode: http.StatusTooManyRequests,
				Headers: map[string]string{
					"X-RateLimit-Remaining": "0",
					"X-RateLimit-Reset":     strconv.Itoa(1234567890),
				},
				Body: map[string]interface{}{
					"error": map[string]interface{}{
						"code":    429,
						"message": "Rate Limit Exceeded",
					},
				},
			})

		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, g.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Try to complete flow
		flow, err := g.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidResponse)
		require.Nil(t, flow)
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
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: expiredFlowID,
			Verifier:   "expired-verifier",
			Challenge:  "expired-challenge",
		})
		require.NoError(t, err)

		// Create a recent flow
		recentFlowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: recentFlowID,
			Verifier:   "recent-verifier",
			Challenge:  "recent-challenge",
		})
		require.NoError(t, err)

		// Create another expired flow
		expiredFlowID2 := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: expiredFlowID2,
			Verifier:   "expired-verifier-2",
			Challenge:  "expired-challenge-2",
		})
		require.NoError(t, err)

		// Mock time.Now to return a time that's Expiry ahead in the future
		// This makes the first two flows appear expired when gc() subtracts Expiry
		futureTime := time.Now().Add(Expiry + 10*time.Minute)
		now = func() time.Time { return futureTime }

		// Create Google instance with mocked time
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}
		g, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = g.Close()
		})

		// Run gc() directly
		deleted, err := g.gc()
		require.NoError(t, err)
		require.Equal(t, int64(3), deleted) // Should delete all 3 flows since they're now "expired"

		// Verify all flows are deleted
		_, err = database.Queries.GetGoogleOAuthFlowByIdentifier(t.Context(), expiredFlowID)
		require.Error(t, err) // Should not exist

		_, err = database.Queries.GetGoogleOAuthFlowByIdentifier(t.Context(), expiredFlowID2)
		require.Error(t, err) // Should not exist

		_, err = database.Queries.GetGoogleOAuthFlowByIdentifier(t.Context(), recentFlowID)
		require.Error(t, err) // Should not exist since with mocked time it's also expired
	})

	t.Run("GCRunsInBackground", func(t *testing.T) {
		// Save the original now function and restore it after the test
		originalNow := now
		t.Cleanup(func() {
			now = originalNow
		})

		// This test verifies that the gc goroutine starts and stops properly
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		g, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, g)

		t.Cleanup(func() {
			_ = g.Close()
		})

		// The gc goroutine should be running now
		// Create a flow that will be expired when we mock the time
		expiredFlowID := uuid.New().String()
		err = database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
			Identifier: expiredFlowID,
			Verifier:   "expired-verifier",
			Challenge:  "expired-challenge",
		})
		require.NoError(t, err)

		// Mock time to make the flow appear expired
		futureTime := time.Now().Add(Expiry + 10*time.Minute)
		now = func() time.Time { return futureTime }

		// Manually trigger gc to verify it works
		deleted, err := g.gc()
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		// Close should stop the gc goroutine gracefully
		err = g.Close()
		require.NoError(t, err)

		// After close, the goroutine should have stopped
		// We can't easily test the goroutine is stopped, but Close() should return without hanging
	})

	t.Run("GCHandlesEmptyTable", func(t *testing.T) {
		// Ensure table is empty
		_, err := database.Queries.DeleteAllGoogleOAuthFlows(t.Context())
		require.NoError(t, err)

		// Run cleanup on empty table
		deleted, err := database.Queries.DeleteGoogleOAuthFlowsBeforeTime(t.Context(), time.Now())
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted) // No rows deleted
	})

	t.Run("GCHandlesNoExpiredFlows", func(t *testing.T) {
		// Create only recent flows
		for i := 0; i < 3; i++ {
			flowID := uuid.New().String()
			err := database.Queries.CreateGoogleOAuthFlow(t.Context(), generated.CreateGoogleOAuthFlowParams{
				Identifier: flowID,
				Verifier:   fmt.Sprintf("verifier-%d", i),
				Challenge:  fmt.Sprintf("challenge-%d", i),
			})
			require.NoError(t, err)
		}

		// Run cleanup with a time that won't match any flows
		deleted, err := database.Queries.DeleteGoogleOAuthFlowsBeforeTime(t.Context(), time.Now().Add(-5*time.Minute))
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted) // No rows should be deleted

		// Verify all flows still exist
		count, err := database.Queries.CountAllGoogleOAuthFlows(t.Context())
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
		_, err := database.Queries.DeleteAllGoogleOAuthFlows(t.Context())
		require.NoError(t, err)

		baseTime := time.Now()

		// Mock time to be exactly at baseTime + Expiry so gc() will delete flows older than now
		now = func() time.Time { return baseTime.Add(Expiry) }

		// Create Google instance with mocked time
		opts := &Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}
		g, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = g.Close()
		})

		var ids []string
		for i := 0; i < 3; i++ {
			redirectURL, err := g.CreateFlow(t.Context(), "", "", "")
			require.NoError(t, err)
			u, err := url.Parse(redirectURL)
			require.NoError(t, err)
			v := u.Query().Get("state")
			ids = append(ids, v)
		}

		// Run gc() directly
		deleted, err := g.gc()
		require.NoError(t, err)
		require.Equal(t, int64(3), deleted)

		for _, id := range ids {
			_, err = database.Queries.GetGoogleOAuthFlowByIdentifier(t.Context(), id)
			require.ErrorContains(t, err, "no rows in result set")
		}
	})
}
