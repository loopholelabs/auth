//SPDX-License-Identifier: Apache-2.0

package github

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
			"scope":        "user:email",
		},
	}
}

// Helper function to create GitHub user response
func mockGitHubUserResponse(id int64, name string) testutils.MockResponse { //nolint:unparam
	return testutils.MockResponse{
		StatusCode: http.StatusOK,
		Body: map[string]interface{}{
			"id":   id,
			"name": name,
		},
	}
}

// Helper function to create GitHub emails response
func mockGitHubEmailsResponse(emails []map[string]interface{}) testutils.MockResponse {
	return testutils.MockResponse{
		StatusCode: http.StatusOK,
		Body:       emails,
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
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, gh)
		require.Equal(t, http.DefaultClient, gh.httpClient)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})
	})

	t.Run("ValidOptionsWithCustomClient", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, gh)
		require.Equal(t, mockClient.HTTPClient, gh.httpClient)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})
	})

	t.Run("MissingRedirectURL", func(t *testing.T) {
		opts := Options{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		gh, err := New(opts, database, logger)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, gh)
	})

	t.Run("MissingClientID", func(t *testing.T) {
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientSecret: "test-client-secret",
		}

		gh, err := New(opts, database, logger)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, gh)
	})

	t.Run("MissingClientSecret", func(t *testing.T) {
		opts := Options{
			RedirectURL: "http://localhost:8080/callback",
			ClientID:    "test-client-id",
		}

		gh, err := New(opts, database, logger)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, gh)
	})

	t.Run("NilDatabase", func(t *testing.T) {
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		gh, err := New(opts, nil, logger)
		require.ErrorIs(t, err, ErrDBIsRequired)
		require.Nil(t, gh)
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

	opts := Options{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	gh, err := New(opts, database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, gh.Close())
	})

	t.Run("CreateFlowSuccess", func(t *testing.T) {
		authURL, err := gh.CreateFlow(t.Context(), "", "", "http://localhost:3000/dashboard")
		require.NoError(t, err)
		require.NotEmpty(t, authURL)

		// Parse the auth URL to validate it
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		require.Equal(t, "github.com", u.Host)
		require.Equal(t, "/login/oauth/authorize", u.Path)

		// Check query parameters
		q := u.Query()
		require.Equal(t, "test-client-id", q.Get("client_id"))
		require.Equal(t, "http://localhost:8080/callback", q.Get("redirect_uri"))
		require.Equal(t, "code", q.Get("response_type"))
		require.Equal(t, "user:email", q.Get("scope"))
		require.NotEmpty(t, q.Get("state")) // This is the flow identifier
		require.NotEmpty(t, q.Get("code_challenge"))
		require.Equal(t, "S256", q.Get("code_challenge_method"))

		// Verify flow was created in database
		flowID := q.Get("state")
		flow, err := database.Queries.GetGithubOAuthFlowByIdentifier(t.Context(), flowID)
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

		authURL, err := gh.CreateFlow(t.Context(), "", userID, "http://example.com/next")
		require.NoError(t, err)
		require.NotEmpty(t, authURL)

		// Parse and get flow ID
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		flowID := u.Query().Get("state")

		// Verify flow was created with user ID
		flow, err := database.Queries.GetGithubOAuthFlowByIdentifier(t.Context(), flowID)
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
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			mockOAuth2TokenResponse("test-access-token"))

		mockClient.SetResponse("https://api.github.com/user",
			mockGitHubUserResponse(12345, "Test User"))

		mockClient.SetResponse("https://api.github.com/user/emails",
			mockGitHubEmailsResponse([]map[string]interface{}{
				{
					"email":    "test@example.com",
					"verified": true,
					"primary":  true,
				},
				{
					"email":    "secondary@example.com",
					"verified": true,
					"primary":  false,
				},
			}))

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow first
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
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
		flow, err := gh.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.NoError(t, err)
		require.NotNil(t, flow)

		// Verify flow data
		require.Equal(t, "12345", flow.Identifier)
		require.Equal(t, "Test User", flow.Name)
		require.Equal(t, "test@example.com", flow.PrimaryEmail)
		require.Len(t, flow.VerifiedEmails, 2)
		require.Contains(t, flow.VerifiedEmails, "test@example.com")
		require.Contains(t, flow.VerifiedEmails, "secondary@example.com")
		require.Equal(t, "http://localhost:3000/dashboard", flow.NextURL)
		require.Empty(t, flow.DeviceIdentifier)
		require.Empty(t, flow.UserIdentifier)

		// Verify flow was deleted from database
		_, err = database.Queries.GetGithubOAuthFlowByIdentifier(t.Context(), flowID)
		require.Error(t, err)

		// Verify HTTP requests were made
		mockClient.AssertRequestMade(t, "github.com/login/oauth/access_token")
		mockClient.AssertRequestMade(t, "api.github.com/user")
		mockClient.AssertRequestMade(t, "api.github.com/user/emails")
		mockClient.AssertNumberOfRequests(t, 3)
	})

	t.Run("CompleteFlowWithNoVerifiedEmails", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			mockOAuth2TokenResponse("test-access-token"))

		mockClient.SetResponse("https://api.github.com/user",
			mockGitHubUserResponse(12345, "Test User"))

		// No verified emails
		mockClient.SetResponse("https://api.github.com/user/emails",
			mockGitHubEmailsResponse([]map[string]interface{}{
				{
					"email":    "unverified@example.com",
					"verified": false,
					"primary":  true,
				},
			}))

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to no verified emails
		flow, err := gh.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoVerifiedEmails)
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithInvalidCode", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// OAuth2 token exchange fails
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			testutils.MockResponse{
				StatusCode: http.StatusBadRequest,
				Body: map[string]interface{}{
					"error":             "bad_verification_code",
					"error_description": "The code passed is incorrect or expired.",
				},
			})

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to invalid code
		flow, err := gh.CompleteFlow(t.Context(), flowID, "invalid-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithGitHubAPIError", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			mockOAuth2TokenResponse("test-access-token"))

		// GitHub API returns error
		mockClient.SetResponse("https://api.github.com/user",
			testutils.MockResponse{
				StatusCode: http.StatusUnauthorized,
				Body:       `{"message": "Bad credentials"}`,
			})

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to API error
		flow, err := gh.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidResponse)
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithNetworkError", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			mockOAuth2TokenResponse("test-access-token"))

		mockClient.SetResponse("https://api.github.com/user",
			mockGitHubUserResponse(12345, "Test User"))

		// Network error for emails endpoint
		mockClient.SetResponse("https://api.github.com/user/emails",
			testutils.MockResponse{
				Error: errors.New("network timeout"),
			})

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to network error
		flow, err := gh.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Contains(t, err.Error(), "network timeout")
		require.Nil(t, flow)
	})

	t.Run("CompleteFlowWithNonexistentFlow", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Try to complete a non-existent flow
		flow, err := gh.CompleteFlow(t.Context(), "nonexistent-flow-id", "test-auth-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)
		require.Nil(t, flow)

		// No HTTP requests should have been made
		mockClient.AssertNumberOfRequests(t, 0)
	})

	t.Run("CompleteFlowWithInvalidJSON", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			mockOAuth2TokenResponse("test-access-token"))

		// Invalid JSON response from user endpoint
		mockClient.SetResponse("https://api.github.com/user",
			testutils.MockResponse{
				StatusCode: http.StatusOK,
				Body:       "not valid json",
			})

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete the flow - should fail due to invalid JSON
		flow, err := gh.CompleteFlow(t.Context(), flowID, "test-auth-code")
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

	opts := Options{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	gh, err := New(opts, database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, gh.Close())
	})

	t.Run("ValidateAuthURLParameters", func(t *testing.T) {
		authURL, err := gh.CreateFlow(t.Context(), "", "", "")
		require.NoError(t, err)

		// Parse URL and validate OAuth2 parameters
		u, err := url.Parse(authURL)
		require.NoError(t, err)

		// Validate base URL
		require.Equal(t, "https", u.Scheme)
		require.Equal(t, "github.com", u.Host)
		require.Equal(t, "/login/oauth/authorize", u.Path)

		// Validate query parameters
		q := u.Query()

		// Standard OAuth2 parameters
		require.Equal(t, "test-client-id", q.Get("client_id"))
		require.Equal(t, "http://localhost:8080/callback", q.Get("redirect_uri"))
		require.Equal(t, "code", q.Get("response_type"))
		require.Equal(t, "online", q.Get("access_type"))
		require.Equal(t, "user:email", q.Get("scope"))

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
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Validate OAuth2 config
		require.NotNil(t, gh.config)
		require.Equal(t, "test-client-id", gh.config.ClientID)
		require.Equal(t, "test-client-secret", gh.config.ClientSecret)
		require.Equal(t, "http://localhost:8080/callback", gh.config.RedirectURL)
		require.Equal(t, []string{"user:email"}, gh.config.Scopes)

		// Validate GitHub endpoints
		require.Equal(t, "https://github.com/login/oauth/authorize", gh.config.Endpoint.AuthURL)
		require.Equal(t, "https://github.com/login/oauth/access_token", gh.config.Endpoint.TokenURL)
	})

	t.Run("CustomHTTPClientPropagation", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Mock the token exchange to verify custom client is used
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			mockOAuth2TokenResponse("test-access-token"))

		// Mock GitHub API responses
		mockClient.SetResponse("https://api.github.com/user",
			mockGitHubUserResponse(12345, "Test User"))

		mockClient.SetResponse("https://api.github.com/user/emails",
			mockGitHubEmailsResponse([]map[string]interface{}{
				{
					"email":    "test@example.com",
					"verified": true,
					"primary":  true,
				},
			}))

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create and complete a flow to verify custom client is used

		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Complete flow - this should use the custom HTTP client
		flow, err := gh.CompleteFlow(t.Context(), flowID, "test-auth-code")
		require.NoError(t, err)
		require.NotNil(t, flow)

		// Verify all requests were made through the custom client
		requests := mockClient.GetRequests()
		require.Len(t, requests, 3)

		// Check request order and URLs
		require.Contains(t, requests[0].URL, "github.com/login/oauth/access_token")
		require.Contains(t, requests[1].URL, "api.github.com/user")
		require.Contains(t, requests[2].URL, "api.github.com/user/emails")

		// Verify authorization header was set correctly
		require.Equal(t, "token test-access-token", requests[1].Headers.Get("Authorization"))
		require.Equal(t, "token test-access-token", requests[2].Headers.Get("Authorization"))
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
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			testutils.MockResponse{
				StatusCode: http.StatusBadRequest,
				Body: map[string]interface{}{
					"error":             "invalid_grant",
					"error_description": "The provided authorization grant is invalid",
				},
			})

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Try to complete flow
		flow, err := gh.CompleteFlow(t.Context(), flowID, "invalid-code")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrCompletingFlow)

		// oauth2 package wraps the error
		var oauth2Err *oauth2.RetrieveError
		require.ErrorAs(t, err, &oauth2Err)
		require.Nil(t, flow)
	})

	t.Run("GitHubAPIRateLimitError", func(t *testing.T) {
		mockClient := testutils.SetupMockHTTPClient(t)

		// Set up mock responses
		mockClient.SetResponse("https://github.com/login/oauth/access_token",
			mockOAuth2TokenResponse("test-access-token"))

		// GitHub API rate limit error
		mockClient.SetResponse("https://api.github.com/user",
			testutils.MockResponse{
				StatusCode: http.StatusForbidden,
				Headers: map[string]string{
					"X-RateLimit-Remaining": "0",
					"X-RateLimit-Reset":     strconv.Itoa(1234567890),
				},
				Body: map[string]interface{}{
					"message": "API rate limit exceeded",
				},
			})

		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			HTTPClient:   mockClient.HTTPClient,
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, gh.Close())
		})

		// Create a flow
		flowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: flowID,
			Verifier:   "test-verifier",
			Challenge:  "test-challenge",
		})
		require.NoError(t, err)

		// Try to complete flow
		flow, err := gh.CompleteFlow(t.Context(), flowID, "test-auth-code")
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
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: expiredFlowID,
			Verifier:   "expired-verifier",
			Challenge:  "expired-challenge",
		})
		require.NoError(t, err)

		// Create a recent flow
		recentFlowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: recentFlowID,
			Verifier:   "recent-verifier",
			Challenge:  "recent-challenge",
		})
		require.NoError(t, err)

		// Create another expired flow
		expiredFlowID2 := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: expiredFlowID2,
			Verifier:   "expired-verifier-2",
			Challenge:  "expired-challenge-2",
		})
		require.NoError(t, err)

		// Mock time.Now to return a time that's Expiry ahead in the future
		// This makes the first two flows appear expired when gc() subtracts Expiry
		futureTime := time.Now().Add(Expiry + 10*time.Minute)
		now = func() time.Time { return futureTime }

		// Create GitHub instance with mocked time
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}
		gh, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = gh.Close()
		})

		// Run gc() directly
		deleted, err := gh.gc()
		require.NoError(t, err)
		require.Equal(t, int64(3), deleted) // Should delete all 3 flows since they're now "expired"

		// Verify all flows are deleted
		_, err = database.Queries.GetGithubOAuthFlowByIdentifier(t.Context(), expiredFlowID)
		require.Error(t, err) // Should not exist

		_, err = database.Queries.GetGithubOAuthFlowByIdentifier(t.Context(), expiredFlowID2)
		require.Error(t, err) // Should not exist

		_, err = database.Queries.GetGithubOAuthFlowByIdentifier(t.Context(), recentFlowID)
		require.Error(t, err) // Should not exist since with mocked time it's also expired
	})

	t.Run("GCRunsInBackground", func(t *testing.T) {
		// Save the original now function and restore it after the test
		originalNow := now
		t.Cleanup(func() {
			now = originalNow
		})

		// This test verifies that the gc goroutine starts and stops properly
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		gh, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, gh)

		t.Cleanup(func() {
			_ = gh.Close()
		})

		// The gc goroutine should be running now
		// Create a flow that will be expired when we mock the time
		expiredFlowID := uuid.New().String()
		err = database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
			Identifier: expiredFlowID,
			Verifier:   "expired-verifier",
			Challenge:  "expired-challenge",
		})
		require.NoError(t, err)

		// Mock time to make the flow appear expired
		futureTime := time.Now().Add(Expiry + 10*time.Minute)
		now = func() time.Time { return futureTime }

		// Manually trigger gc to verify it works
		deleted, err := gh.gc()
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		// Close should stop the gc goroutine gracefully
		err = gh.Close()
		require.NoError(t, err)

		// After close, the goroutine should have stopped
		// We can't easily test the goroutine is stopped, but Close() should return without hanging
	})

	t.Run("GCHandlesEmptyTable", func(t *testing.T) {
		// Ensure table is empty
		_, err := database.Queries.DeleteAllGithubOAuthFlows(t.Context())
		require.NoError(t, err)

		// Run cleanup on empty table
		deleted, err := database.Queries.DeleteGithubOAuthFlowsBeforeTime(t.Context(), time.Now())
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted) // No rows deleted
	})

	t.Run("GCHandlesNoExpiredFlows", func(t *testing.T) {
		// Create only recent flows
		for i := 0; i < 3; i++ {
			flowID := uuid.New().String()
			err := database.Queries.CreateGithubOAuthFlow(t.Context(), generated.CreateGithubOAuthFlowParams{
				Identifier: flowID,
				Verifier:   fmt.Sprintf("verifier-%d", i),
				Challenge:  fmt.Sprintf("challenge-%d", i),
			})
			require.NoError(t, err)
		}

		// Run cleanup with a time that won't match any flows
		deleted, err := database.Queries.DeleteGithubOAuthFlowsBeforeTime(t.Context(), time.Now().Add(-5*time.Minute))
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted) // No rows should be deleted

		// Verify all flows still exist
		count, err := database.Queries.CountAllGithubOAuthFlows(t.Context())
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
		_, err := database.Queries.DeleteAllGithubOAuthFlows(t.Context())
		require.NoError(t, err)

		baseTime := time.Now()

		// Mock time to be exactly at baseTime + Expiry so gc() will delete flows older than now
		now = func() time.Time { return baseTime.Add(Expiry) }

		// Create GitHub instance with mocked time
		opts := Options{
			RedirectURL:  "http://localhost:8080/callback",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}
		gh, err := New(opts, database, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = gh.Close()
		})

		var ids []string
		for i := 0; i < 3; i++ {
			redirectURL, err := gh.CreateFlow(t.Context(), "", "", "")
			require.NoError(t, err)
			u, err := url.Parse(redirectURL)
			require.NoError(t, err)
			v := u.Query().Get("state")
			ids = append(ids, v)
		}

		// Run gc() directly
		deleted, err := gh.gc()
		require.NoError(t, err)
		require.Equal(t, int64(3), deleted)

		for _, id := range ids {
			_, err = database.Queries.GetGithubOAuthFlowByIdentifier(t.Context(), id)
			require.ErrorContains(t, err, "no rows in result set")
		}
	})
}
