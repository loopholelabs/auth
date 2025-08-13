//SPDX-License-Identifier: Apache-2.0

package github

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/testutils"
	"github.com/loopholelabs/auth/pkg/api/options"
	"github.com/loopholelabs/auth/pkg/manager"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
)

func setupTestEnvironment(t *testing.T, enableGitHub bool) humatest.TestAPI {
	// Setup MySQL container
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	// Create manager options
	mgrOpts := manager.Options{
		Configuration: configuration.Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Hour,
		},
		API: manager.APIOptions{
			TLS:      false,
			Endpoint: "localhost:8080",
		},
	}

	if enableGitHub {
		mgrOpts.Github = manager.GithubOptions{
			Enabled:      true,
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}
	}

	// Create manager
	mgr, err := manager.New(mgrOpts, database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, mgr.Close())
	})

	// Create options for the GitHub handler
	opts := options.Options{
		Manager:  mgr,
		Endpoint: "localhost:8080",
		TLS:      false,
	}

	// Create GitHub handler
	gh := New(opts, logger)

	// Create test API
	_, api := humatest.New(t)

	// Register GitHub endpoints
	gh.Register([]string{"flows"}, api)

	return api
}

func TestGitHubLogin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		api := setupTestEnvironment(t, true)

		resp := api.Get("/github/login?next=/")
		assert.Equal(t, 307, resp.Result().StatusCode)

		// The redirect is in the response body for test API
		// Just verify we got a redirect response
	})

	t.Run("WithNext", func(t *testing.T) {
		api := setupTestEnvironment(t, true)

		resp := api.Get("/github/login?next=/dashboard")
		assert.Equal(t, 307, resp.Result().StatusCode)
	})

	t.Run("GitHubNotEnabled", func(t *testing.T) {
		api := setupTestEnvironment(t, false)

		resp := api.Get("/github/login?next=/")
		assert.Equal(t, 401, resp.Result().StatusCode)

		// Parse error response
		var errorResp map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
		require.NoError(t, err)
		assert.Equal(t, "github provider is not enabled", errorResp["detail"])
	})
}

func TestGitHubCallback(t *testing.T) {
	t.Run("MissingState", func(t *testing.T) {
		api := setupTestEnvironment(t, true)

		resp := api.Get("/github/callback?code=test-code")
		assert.Equal(t, 422, resp.Result().StatusCode)
	})

	t.Run("MissingCode", func(t *testing.T) {
		api := setupTestEnvironment(t, true)

		resp := api.Get("/github/callback?state=test-state")
		assert.Equal(t, 422, resp.Result().StatusCode)
	})

	t.Run("InvalidState", func(t *testing.T) {
		api := setupTestEnvironment(t, true)

		resp := api.Get("/github/callback?state=invalid-state&code=test-code")
		assert.Equal(t, 404, resp.Result().StatusCode)
	})

	t.Run("GitHubNotEnabled", func(t *testing.T) {
		api := setupTestEnvironment(t, false)

		resp := api.Get("/github/callback?state=test-state&code=test-code")
		assert.Equal(t, 401, resp.Result().StatusCode)
	})
}
