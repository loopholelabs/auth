//SPDX-License-Identifier: Apache-2.0

package device

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

func setupTestEnvironment(t *testing.T) humatest.TestAPI {
	// Setup PostgreSQL container
	container := testutils.SetupPostgreSQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	// Create manager with device flow enabled
	mgr, err := manager.New(manager.Options{
		Configuration: configuration.Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Hour,
		},
		API: manager.APIOptions{
			TLS:      false,
			Endpoint: "localhost:8080",
		},
		Device: manager.DeviceOptions{
			Enabled: true,
		},
	}, database, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, mgr.Close())
	})

	// Create options for the Device handler
	opts := options.Options{
		Manager:  mgr,
		Endpoint: "localhost:8080",
		TLS:      false,
	}

	// Create Device handler
	device := New(opts, logger)

	// Create test API
	_, api := humatest.New(t)

	// Register device endpoints
	device.Register([]string{"flows"}, api)

	return api
}

func TestDeviceLogin(t *testing.T) {
	api := setupTestEnvironment(t)

	t.Run("Success", func(t *testing.T) {
		resp := api.Get("/device/login")
		assert.Equal(t, 200, resp.Result().StatusCode)

		// Parse response
		var result DeviceLoginResponseBody
		err := json.Unmarshal(resp.Body.Bytes(), &result)
		require.NoError(t, err)

		// Verify response contains required fields
		assert.NotEmpty(t, result.Code)
		assert.NotEmpty(t, result.Poll)
		assert.Equal(t, uint64(5), result.PollingRateSeconds)
	})
}

func TestDeviceValidate(t *testing.T) {
	api := setupTestEnvironment(t)

	t.Run("ValidCode", func(t *testing.T) {
		// First create a device flow
		loginResp := api.Get("/device/login")
		require.Equal(t, 200, loginResp.Result().StatusCode)

		var loginResult DeviceLoginResponseBody
		err := json.Unmarshal(loginResp.Body.Bytes(), &loginResult)
		require.NoError(t, err)

		// Now validate with the user code
		resp := api.Get("/device/validate?code=" + loginResult.Code)
		assert.Equal(t, 200, resp.Result().StatusCode)
	})

	t.Run("InvalidCode", func(t *testing.T) {
		resp := api.Get("/device/validate?code=INVALID8") // 8 chars to pass validation
		assert.Equal(t, 404, resp.Result().StatusCode)
	})

	t.Run("MissingCode", func(t *testing.T) {
		resp := api.Get("/device/validate")
		// Should fail validation
		assert.Equal(t, 422, resp.Result().StatusCode)
	})
}

func TestDevicePoll(t *testing.T) {
	api := setupTestEnvironment(t)

	t.Run("InvalidPollCode", func(t *testing.T) {
		resp := api.Get("/device/poll?poll=00000000-0000-0000-0000-000000000000")
		assert.Equal(t, 404, resp.Result().StatusCode)
	})

	t.Run("MissingPollCode", func(t *testing.T) {
		resp := api.Get("/device/poll")
		// Should fail validation
		assert.Equal(t, 422, resp.Result().StatusCode)
	})
}
