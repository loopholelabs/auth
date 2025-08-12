//SPDX-License-Identifier: Apache-2.0

package google

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
	"github.com/loopholelabs/auth/pkg/validator"
)

func setupTestEnvironment(t *testing.T, enableGoogle bool) (*Google, humatest.TestAPI) {
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

	if enableGoogle {
		mgrOpts.Google = manager.GoogleOptions{
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

	// Create validator
	val, err := validator.New(validator.Options{
		Configuration: configuration.Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Hour,
		},
	}, database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, val.Close())
	})

	// Create options for the Google handler
	opts := options.Options{
		Manager:   mgr,
		Validator: val,
		Endpoint:  "localhost:8080",
		TLS:       false,
	}

	// Create Google handler
	g := New(opts, logger)

	// Create test API
	_, api := humatest.New(t)

	// Register Google endpoints
	g.Register([]string{"flows"}, api)

	return g, api
}

func TestGoogleLogin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/google/login?next=/")
		assert.Equal(t, 307, resp.Result().StatusCode)

		// The redirect is in the response body for test API
		// Just verify we got a redirect response
	})

	t.Run("WithNext", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/google/login?next=/dashboard")
		assert.Equal(t, 307, resp.Result().StatusCode)
	})

	t.Run("GoogleNotEnabled", func(t *testing.T) {
		_, api := setupTestEnvironment(t, false)

		resp := api.Get("/google/login?next=/")
		assert.Equal(t, 401, resp.Result().StatusCode)

		// Parse error response
		var errorResp map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
		require.NoError(t, err)
		assert.Equal(t, "google provider is not enabled", errorResp["detail"])
	})

	t.Run("MissingNext", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/google/login")
		assert.Equal(t, 422, resp.Result().StatusCode)

		// Parse error response
		var errorResp map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
		require.NoError(t, err)
		assert.Equal(t, "validation failed", errorResp["detail"])
	})
}

func TestGoogleCallback(t *testing.T) {
	t.Run("MissingState", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/google/callback?code=test-code")
		assert.Equal(t, 422, resp.Result().StatusCode)
	})

	t.Run("MissingCode", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/google/callback?state=test-state")
		assert.Equal(t, 422, resp.Result().StatusCode)
	})

	t.Run("InvalidState", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/google/callback?state=invalid-state&code=test-code")
		assert.Equal(t, 404, resp.Result().StatusCode)
	})

	t.Run("GoogleNotEnabled", func(t *testing.T) {
		_, api := setupTestEnvironment(t, false)

		resp := api.Get("/google/callback?state=test-state&code=test-code")
		assert.Equal(t, 401, resp.Result().StatusCode)
	})
}
