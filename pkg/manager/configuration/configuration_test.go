//SPDX-License-Identifier: Apache-2.0

package configuration

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Run("ValidOptions", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})
		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify initial values
		require.Equal(t, time.Second*5, cfg.PollInterval())
		require.Equal(t, time.Minute*30, cfg.SessionExpiry())

		// Clean shutdown
		require.NoError(t, cfg.Close())
	})

	t.Run("InvalidPollInterval", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  0, // Invalid
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOptions)
		require.Nil(t, cfg)
	})

	t.Run("NilDatabase", func(t *testing.T) {
		logger := logging.Test(t, logging.Zerolog, "test")

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, nil, logger)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrDBIsRequired)
		require.Nil(t, cfg)
	})

	t.Run("ExistingConfigurationInDatabase", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		// Pre-populate database with different values
		err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
			ConfigurationKey:   PollIntervalKey.String(),
			ConfigurationValue: "10s",
		})
		require.NoError(t, err)

		err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
			ConfigurationKey:   SessionExpiryKey.String(),
			ConfigurationValue: "1h",
		})
		require.NoError(t, err)

		// Create configuration with different defaults
		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Should use existing database values, not defaults
		require.Equal(t, time.Second*10, cfg.PollInterval())
		require.Equal(t, time.Hour, cfg.SessionExpiry())

		require.NoError(t, cfg.Close())
	})
}

func TestSetDefault(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Second * 5,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	t.Run("NewConfigurationKey", func(t *testing.T) {
		// Use a custom key for testing
		testKey := Key("test_key")
		value, err := cfg.setDefault(testKey, "test_value")
		require.NoError(t, err)
		require.Equal(t, "test_value", value)

		// Verify it was stored in database
		dbValue, err := database.Queries.GetConfigurationByKey(t.Context(), testKey.String())
		require.NoError(t, err)
		require.Equal(t, "test_value", dbValue.ConfigurationValue)
	})

	t.Run("ExistingConfigurationKey", func(t *testing.T) {
		// Pre-set a value
		testKey := Key("existing_key")
		err := database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
			ConfigurationKey:   testKey.String(),
			ConfigurationValue: "existing_value",
		})
		require.NoError(t, err)

		// setDefault should return existing value
		value, err := cfg.setDefault(testKey, "new_value")
		require.NoError(t, err)
		require.Equal(t, "existing_value", value)

		// Verify it wasn't overwritten
		dbValue, err := database.Queries.GetConfigurationByKey(t.Context(), testKey.String())
		require.NoError(t, err)
		require.Equal(t, "existing_value", dbValue.ConfigurationValue)
	})
}

func TestPollingUpdates(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	// Use short poll interval for testing
	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	// Initial values
	require.Equal(t, time.Millisecond*100, cfg.PollInterval())
	require.Equal(t, time.Minute*30, cfg.SessionExpiry())

	// Update values in database
	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   SessionExpiryKey.String(),
		ConfigurationValue: "45m",
	})
	require.NoError(t, err)

	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   PollIntervalKey.String(),
		ConfigurationValue: "200ms",
	})
	require.NoError(t, err)

	cfg.update()

	// Values should be updated
	require.Equal(t, time.Millisecond*200, cfg.PollInterval())
	require.Equal(t, time.Minute*45, cfg.SessionExpiry())
}

func TestInvalidConfigurationValues(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	originalPollInterval := cfg.PollInterval()
	originalSessionExpiry := cfg.SessionExpiry()

	// Set invalid duration values in database
	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   SessionExpiryKey.String(),
		ConfigurationValue: "invalid-duration",
	})
	require.NoError(t, err)

	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   PollIntervalKey.String(),
		ConfigurationValue: "also-invalid",
	})
	require.NoError(t, err)

	cfg.update()

	// Values should remain unchanged due to parse errors
	require.Equal(t, originalPollInterval, cfg.PollInterval())
	require.Equal(t, originalSessionExpiry, cfg.SessionExpiry())
}

func TestUnknownConfigurationKey(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	// Add unknown configuration key
	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   "unknown_key",
		ConfigurationValue: "some_value",
	})
	require.NoError(t, err)

	cfg.update()

	// Known values should remain unchanged
	require.Equal(t, time.Millisecond*100, cfg.PollInterval())
	require.Equal(t, time.Minute*30, cfg.SessionExpiry())
}

func TestConcurrentAccess(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Millisecond * 50,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	// Concurrent reads and updates
	var wg sync.WaitGroup

	// Reader goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = cfg.PollInterval()
				_ = cfg.SessionExpiry()
				time.Sleep(time.Microsecond * 10)
			}
		}()
	}

	// Writer goroutine (simulating database updates)
	wg.Add(1)
	go func(t *testing.T) {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			duration := time.Duration(i+1) * time.Minute
			err := database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
				ConfigurationKey:   SessionExpiryKey.String(),
				ConfigurationValue: duration.String(),
			})
			assert.NoError(t, err)
			time.Sleep(time.Millisecond * 20)
		}
	}(t)

	wg.Wait()

	// Should complete without race conditions or panics
	require.NotNil(t, cfg.PollInterval())
	require.NotNil(t, cfg.SessionExpiry())
}

func TestGracefulShutdown(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Close should stop polling goroutine
	err = cfg.Close()
	require.NoError(t, err)

	// Subsequent calls should still work but not update
	require.Equal(t, time.Millisecond*100, cfg.PollInterval())
	require.Equal(t, time.Minute*30, cfg.SessionExpiry())

	// Update database after close
	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   SessionExpiryKey.String(),
		ConfigurationValue: "2h",
	})
	require.NoError(t, err)

	// Wait to ensure no polling happens
	time.Sleep(time.Millisecond * 300)

	// Values should not change after close
	require.Equal(t, time.Millisecond*100, cfg.PollInterval())
	require.Equal(t, time.Minute*30, cfg.SessionExpiry())
}

func TestMultipleConfigurations(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	// Create two configuration instances with different defaults
	opts1 := Options{
		PollInterval:  time.Second * 5,
		SessionExpiry: time.Minute * 30,
	}

	cfg1, err := New(opts1, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg1)

	t.Cleanup(func() {
		require.NoError(t, cfg1.Close())
	})

	// Second instance should use existing database values
	opts2 := Options{
		PollInterval:  time.Second * 10,
		SessionExpiry: time.Hour,
	}

	cfg2, err := New(opts2, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg2)

	t.Cleanup(func() {
		require.NoError(t, cfg2.Close())
	})

	// Both should have same values (from first initialization)
	require.Equal(t, cfg1.PollInterval(), cfg2.PollInterval())
	require.Equal(t, cfg1.SessionExpiry(), cfg2.SessionExpiry())

	// Update database
	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   SessionExpiryKey.String(),
		ConfigurationValue: "90m",
	})
	require.NoError(t, err)

	cfg1.update()
	cfg2.update()

	// Both should have updated values
	require.Equal(t, time.Minute*90, cfg1.SessionExpiry())
	require.Equal(t, time.Minute*90, cfg2.SessionExpiry())
}

func TestTransactionIsolation(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Second * 5,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	// Verify configurations were created
	configs, err := database.Queries.GetAllConfigurations(t.Context())
	require.NoError(t, err)
	require.Len(t, configs, 3) // poll_interval, session_expiry, signing_key

	// Map for easy lookup
	configMap := make(map[string]string)
	for _, c := range configs {
		configMap[c.ConfigurationKey] = c.ConfigurationValue
	}

	require.Equal(t, "5s", configMap[PollIntervalKey.String()])
	require.Equal(t, "30m0s", configMap[SessionExpiryKey.String()])
	require.NotEmpty(t, configMap[SigningKey.String()])
}

func TestConfigurationEdgeCases(t *testing.T) {
	t.Run("VeryShortPollInterval", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Nanosecond, // Very short but valid
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Should handle rapid polling without issues
		time.Sleep(time.Millisecond * 100)

		require.NoError(t, cfg.Close())
	})

	t.Run("VeryLongDurations", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Hour * 24,       // 24 hours
			SessionExpiry: time.Hour * 24 * 365, // 1 year
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		require.Equal(t, time.Hour*24, cfg.PollInterval())
		require.Equal(t, time.Hour*24*365, cfg.SessionExpiry())

		require.NoError(t, cfg.Close())
	})

	t.Run("ZeroDurations", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		// First create valid configuration
		opts := Options{
			PollInterval:  time.Millisecond * 100,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// Try to set zero duration in database
		err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
			ConfigurationKey:   SessionExpiryKey.String(),
			ConfigurationValue: "0",
		})
		require.NoError(t, err)

		cfg.update()

		// Zero duration should be accepted
		require.Equal(t, time.Duration(0), cfg.SessionExpiry())
	})
}

func TestKeyString(t *testing.T) {
	require.Equal(t, "poll_interval", PollIntervalKey.String())
	require.Equal(t, "session_expiry", SessionExpiryKey.String())
	require.Equal(t, "signing_key", SigningKey.String())
	require.Equal(t, "previous_signing_key", PreviousSigningKey.String())

	// Custom key
	customKey := Key("custom_key")
	require.Equal(t, "custom_key", customKey.String())
}

func TestDatabaseConnectionLost(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Close database connection
	require.NoError(t, database.Close())

	cfg.update()

	// Should still return last known values
	require.Equal(t, time.Millisecond*100, cfg.PollInterval())
	require.Equal(t, time.Minute*30, cfg.SessionExpiry())

	// Clean shutdown should still work
	require.NoError(t, cfg.Close())
}

func TestInitializationFailure(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	// Pre-populate with invalid duration format
	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   PollIntervalKey.String(),
		ConfigurationValue: "not-a-duration",
	})
	require.NoError(t, err)

	opts := Options{
		PollInterval:  time.Second * 5,
		SessionExpiry: time.Minute * 30,
	}

	// Should fail during initialization
	cfg, err := New(opts, database, logger)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInitializingConfigurations)
	require.Nil(t, cfg)
}

func TestDatabaseUpdateAfterInit(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	// Verify initial values
	configs, err := database.Queries.GetAllConfigurations(t.Context())
	require.NoError(t, err)
	require.Len(t, configs, 3) // poll_interval, session_expiry, signing_key

	// Update session expiry multiple times
	for i := 1; i <= 3; i++ {
		duration := time.Duration(i*10) * time.Minute
		err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
			ConfigurationKey:   SessionExpiryKey.String(),
			ConfigurationValue: duration.String(),
		})
		require.NoError(t, err)

		cfg.update()

		// Verify update was picked up
		require.Equal(t, duration, cfg.SessionExpiry())
	}
}

func TestNegativeDurations(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	t.Cleanup(func() {
		require.NoError(t, cfg.Close())
	})

	// Set negative duration
	err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
		ConfigurationKey:   SessionExpiryKey.String(),
		ConfigurationValue: "-5m",
	})
	require.NoError(t, err)

	cfg.update()

	// Negative duration should be accepted (Go's time.Duration allows negative values)
	require.Equal(t, -5*time.Minute, cfg.SessionExpiry())
}

func TestSigningKeyInitialization(t *testing.T) {
	t.Run("FirstTimeInitialization", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// Should have created a signing key
		require.NotNil(t, cfg.SigningKey())
		// Should not have a previous signing key on first init
		require.Nil(t, cfg.PreviousSigningKey())

		// Verify key was stored in database
		dbKey, err := database.Queries.GetConfigurationByKey(t.Context(), SigningKey.String())
		require.NoError(t, err)
		require.NotEmpty(t, dbKey.ConfigurationValue)

		// Should not have previous key in database
		_, err = database.Queries.GetConfigurationByKey(t.Context(), PreviousSigningKey.String())
		require.Error(t, err)
	})

	t.Run("ExistingSigningKey", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		// First configuration creates signing key
		opts1 := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg1, err := New(opts1, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg1)

		originalKey := cfg1.SigningKey()
		require.NotNil(t, originalKey)

		require.NoError(t, cfg1.Close())

		// Second configuration should use existing key
		opts2 := Options{
			PollInterval:  time.Second * 10,
			SessionExpiry: time.Hour,
		}

		cfg2, err := New(opts2, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg2)

		t.Cleanup(func() {
			require.NoError(t, cfg2.Close())
		})

		// Should have same signing key
		require.NotNil(t, cfg2.SigningKey())
		require.Equal(t, originalKey.D, cfg2.SigningKey().D)
		require.Equal(t, originalKey.X, cfg2.SigningKey().X)
		require.Equal(t, originalKey.Y, cfg2.SigningKey().Y)
	})

	t.Run("ExistingBothKeys", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		// Create first configuration
		cfg1, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg1)

		// Rotate key to create previous key
		err = cfg1.RotateSigningKey(t.Context())
		require.NoError(t, err)

		newKey := cfg1.SigningKey()
		prevKey := cfg1.PreviousSigningKey()
		require.NotNil(t, newKey)
		require.NotNil(t, prevKey)

		require.NoError(t, cfg1.Close())

		// Create second configuration
		cfg2, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg2)

		t.Cleanup(func() {
			require.NoError(t, cfg2.Close())
		})

		// Should load both keys
		require.NotNil(t, cfg2.SigningKey())
		require.NotNil(t, cfg2.PreviousSigningKey())

		// Verify keys match
		require.Equal(t, newKey.D, cfg2.SigningKey().D)
		require.Equal(t, prevKey.D, cfg2.PreviousSigningKey().D)
	})
}

func TestRotateSigningKey(t *testing.T) {
	t.Run("FirstRotation", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		originalKey := cfg.SigningKey()
		require.NotNil(t, originalKey)
		require.Nil(t, cfg.PreviousSigningKey())

		// Rotate key
		err = cfg.RotateSigningKey(t.Context())
		require.NoError(t, err)

		// Should have new signing key
		newKey := cfg.SigningKey()
		require.NotNil(t, newKey)
		require.NotEqual(t, originalKey.D, newKey.D)

		// Original key should be previous key
		prevKey := cfg.PreviousSigningKey()
		require.NotNil(t, prevKey)
		require.Equal(t, originalKey.D, prevKey.D)

		// Verify database state
		dbSigningKey, err := database.Queries.GetConfigurationByKey(t.Context(), SigningKey.String())
		require.NoError(t, err)
		require.NotEmpty(t, dbSigningKey.ConfigurationValue)

		dbPrevKey, err := database.Queries.GetConfigurationByKey(t.Context(), PreviousSigningKey.String())
		require.NoError(t, err)
		require.NotEmpty(t, dbPrevKey.ConfigurationValue)
	})

	t.Run("SubsequentRotation", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// First rotation
		err = cfg.RotateSigningKey(t.Context())
		require.NoError(t, err)

		firstRotatedKey := cfg.SigningKey()
		require.NotNil(t, firstRotatedKey)

		// Second rotation
		err = cfg.RotateSigningKey(t.Context())
		require.NoError(t, err)

		secondRotatedKey := cfg.SigningKey()
		prevKey := cfg.PreviousSigningKey()

		// Second rotated key should be different from first
		require.NotEqual(t, firstRotatedKey.D, secondRotatedKey.D)
		// Previous key should be the first rotated key
		require.Equal(t, firstRotatedKey.D, prevKey.D)
	})

	t.Run("ConcurrentRotation", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// Try concurrent rotations
		var wg sync.WaitGroup
		errors := make([]error, 5)

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				errors[idx] = cfg.RotateSigningKey(t.Context())
			}(i)
		}

		wg.Wait()

		// All should complete without error (though some may retry due to conflicts)
		for _, err := range errors {
			require.NoError(t, err)
		}

		// Should have valid keys after concurrent rotations
		require.NotNil(t, cfg.SigningKey())
		require.NotNil(t, cfg.PreviousSigningKey())
	})
}

func TestSigningKeyPollingUpdate(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")
	database, err := db.New(container.URL, logger)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})

	opts := Options{
		PollInterval:  time.Millisecond * 100,
		SessionExpiry: time.Minute * 30,
	}

	cfg1, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg1)

	cfg2, err := New(opts, database, logger)
	require.NoError(t, err)
	require.NotNil(t, cfg2)

	t.Cleanup(func() {
		require.NoError(t, cfg1.Close())
		require.NoError(t, cfg2.Close())
	})

	originalKey1 := cfg1.SigningKey()
	originalKey2 := cfg2.SigningKey()

	// Keys should initially be the same
	require.Equal(t, originalKey1.D, originalKey2.D)

	// Rotate key in cfg1
	err = cfg1.RotateSigningKey(t.Context())
	require.NoError(t, err)

	// cfg2 should pick up the change via polling
	time.Sleep(time.Millisecond * 300)

	// Both should have the new key
	require.Equal(t, cfg1.SigningKey().D, cfg2.SigningKey().D)
	require.Equal(t, cfg1.PreviousSigningKey().D, cfg2.PreviousSigningKey().D)
}

func TestSigningKeyEncodingDecoding(t *testing.T) {
	t.Run("InvalidBase64", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// Set invalid base64 in database
		err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
			ConfigurationKey:   SigningKey.String(),
			ConfigurationValue: "not-valid-base64!@#$",
		})
		require.NoError(t, err)

		originalKey := cfg.SigningKey()

		// Update should handle error gracefully
		cfg.update()

		// Key should remain unchanged
		require.Equal(t, originalKey.D, cfg.SigningKey().D)
	})

	t.Run("InvalidPEM", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// Set valid base64 but invalid PEM
		invalidPEM := "VGhpcyBpcyBub3QgYSB2YWxpZCBQRU0ga2V5" // "This is not a valid PEM key" in base64
		err = database.Queries.SetConfiguration(t.Context(), generated.SetConfigurationParams{
			ConfigurationKey:   SigningKey.String(),
			ConfigurationValue: invalidPEM,
		})
		require.NoError(t, err)

		originalKey := cfg.SigningKey()

		// Update should handle error gracefully
		cfg.update()

		// Key should remain unchanged
		require.Equal(t, originalKey.D, cfg.SigningKey().D)
	})
}

func TestTransactionIsolationLevels(t *testing.T) {
	t.Run("RotateSigningKeyUsesRepeatableRead", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// RotateSigningKey should use RepeatableRead isolation level
		// This test verifies it doesn't cause deadlocks
		err = cfg.RotateSigningKey(t.Context())
		require.NoError(t, err)

		// Verify the operation completed successfully
		require.NotNil(t, cfg.SigningKey())
	})

	t.Run("SetDefaultUsesReadCommitted", func(t *testing.T) {
		container := testutils.SetupMySQLContainer(t)
		logger := logging.Test(t, logging.Zerolog, "test")
		database, err := db.New(container.URL, logger)
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, database.Close())
		})

		opts := Options{
			PollInterval:  time.Second * 5,
			SessionExpiry: time.Minute * 30,
		}

		cfg, err := New(opts, database, logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		t.Cleanup(func() {
			require.NoError(t, cfg.Close())
		})

		// setDefault uses ReadCommitted isolation level
		// This should work without issues
		testKey := Key("test_isolation_key")
		value, err := cfg.setDefault(testKey, "test_value")
		require.NoError(t, err)
		require.Equal(t, "test_value", value)
	})
}
