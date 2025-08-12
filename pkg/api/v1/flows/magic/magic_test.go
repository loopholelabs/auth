//SPDX-License-Identifier: Apache-2.0

package magic

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

func setupTestEnvironment(t *testing.T, enableMagic bool) (*Magic, humatest.TestAPI) {
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

	if enableMagic {
		mgrOpts.Magic = manager.MagicOptions{
			Enabled: true,
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

	// Create options for the Magic handler
	opts := options.Options{
		Manager:   mgr,
		Validator: val,
		Endpoint:  "localhost:8080",
		TLS:       false,
	}

	// Create Magic handler
	m := New(opts, logger)

	// Create test API
	_, api := humatest.New(t)

	// Register Magic endpoints
	m.Register([]string{"flows"}, api)

	return m, api
}

func TestMagicLogin(t *testing.T) {
	t.Run("MissingEmail", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/magic/login?next=/")
		assert.Equal(t, 422, resp.Result().StatusCode)

		// Parse error response
		var errorResp map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
		require.NoError(t, err)
		assert.Equal(t, "validation failed", errorResp["detail"])
	})

	t.Run("MissingNext", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/magic/login?email=test@example.com")
		assert.Equal(t, 422, resp.Result().StatusCode)
	})

	t.Run("InvalidEmail", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/magic/login?email=invalid-email&next=/")
		// The email validation happens in the handler, not in Huma validation
		// Without a mailer configured, this would fail at the mailer step
		assert.Equal(t, 401, resp.Result().StatusCode)
	})

	t.Run("MagicNotEnabled", func(t *testing.T) {
		_, api := setupTestEnvironment(t, false)

		resp := api.Get("/magic/login?email=test@example.com&next=/")
		assert.Equal(t, 401, resp.Result().StatusCode)

		// Parse error response
		var errorResp map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
		require.NoError(t, err)
		assert.Equal(t, "magic provider is not enabled", errorResp["detail"])
	})

	t.Run("WithValidEmail", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/magic/login?email=test@example.com&next=/dashboard")
		// Without a mailer configured, this would return 401
		assert.Equal(t, 401, resp.Result().StatusCode)

		// Parse error response
		var errorResp map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
		require.NoError(t, err)
		assert.Equal(t, "email provider is not enabled", errorResp["detail"])
	})

	t.Run("WithDeviceCode", func(t *testing.T) {
		// Setup with both Magic and Device enabled
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		mgr, err := manager.New(manager.Options{
			Configuration: configuration.Options{
				PollInterval:  time.Second * 5,
				SessionExpiry: time.Hour,
			},
			API: manager.APIOptions{
				TLS:      false,
				Endpoint: "localhost:8080",
			},
			Magic: manager.MagicOptions{
				Enabled: true,
			},
			Device: manager.DeviceOptions{
				Enabled: true,
			},
		}, database, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, mgr.Close())
		})

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

		opts := options.Options{
			Manager:   mgr,
			Validator: val,
			Endpoint:  "localhost:8080",
			TLS:       false,
		}

		m := New(opts, logger)
		_, api := humatest.New(t)
		m.Register([]string{"flows"}, api)

		// Create a device flow first
		code, _, err := mgr.Device().CreateFlow(t.Context())
		require.NoError(t, err)

		resp := api.Get("/magic/login?email=test@example.com&next=/&code=" + code)
		// Without a mailer, this would return 401
		assert.Equal(t, 401, resp.Result().StatusCode)
	})
}

func TestMagicCallback(t *testing.T) {
	t.Run("MissingToken", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/magic/callback")
		assert.Equal(t, 422, resp.Result().StatusCode)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		_, api := setupTestEnvironment(t, true)

		resp := api.Get("/magic/callback?token=invalid-token")
		assert.Equal(t, 401, resp.Result().StatusCode)

		// Parse error response
		var errorResp map[string]interface{}
		err := json.Unmarshal(resp.Body.Bytes(), &errorResp)
		require.NoError(t, err)
		assert.Equal(t, "invalid token", errorResp["detail"])
	})

	t.Run("MagicNotEnabled", func(t *testing.T) {
		_, api := setupTestEnvironment(t, false)

		resp := api.Get("/magic/callback?token=test-token")
		assert.Equal(t, 401, resp.Result().StatusCode)
	})
}
