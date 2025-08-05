//SPDX-License-Identifier: Apache-2.0

package db

import (
	"testing"

	"github.com/loopholelabs/auth/internal/testutils"
	"github.com/loopholelabs/logging"
	"github.com/stretchr/testify/require"
)

func TestInitialize(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	t.Run("SuccessfulInitialization", func(t *testing.T) {
		err := Initialize(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, Pool)

		// Verify connection pool settings
		stats := Pool.Stats()
		require.Equal(t, 25, stats.MaxOpenConnections)

		// Verify we can query the database
		var result int
		err = Pool.QueryRow("SELECT 1").Scan(&result)
		require.NoError(t, err)
		require.Equal(t, 1, result)

		// Clean up for next test
		Close()
		Pool = nil
	})

	t.Run("MissingParseTimeOption", func(t *testing.T) {
		invalidURL := "root:testpassword@tcp(localhost:3306)/testdb?multiStatements=true"
		err := Initialize(invalidURL, logger)
		require.ErrorIs(t, err, ErrMissingParseTimeOption)
		require.Nil(t, Pool)
	})

	t.Run("MissingMultiStatementsOption", func(t *testing.T) {
		invalidURL := "root:testpassword@tcp(localhost:3306)/testdb?parseTime=true"
		err := Initialize(invalidURL, logger)
		require.ErrorIs(t, err, ErrMissingMultiStatementsOption)
		require.Nil(t, Pool)
	})

	t.Run("InvalidDatabaseURL", func(t *testing.T) {
		invalidURL := "invalid://url?parseTime=true&multiStatements=true"
		err := Initialize(invalidURL, logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to connect to database")
		require.Nil(t, Pool)
	})

	t.Run("UnreachableDatabase", func(t *testing.T) {
		unreachableURL := "root:wrongpassword@tcp(localhost:9999)/testdb?parseTime=true&multiStatements=true"
		err := Initialize(unreachableURL, logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to ping database")
		// Pool may be set but unusable - clean up
		if Pool != nil {
			Pool.Close()
			Pool = nil
		}
	})
}

func TestClose(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	t.Run("CloseValidConnection", func(t *testing.T) {
		err := Initialize(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, Pool)

		// Close should not panic
		require.NotPanics(t, func() {
			Close()
		})

		// Verify connection is closed
		err = Pool.Ping()
		require.Error(t, err)
		require.Contains(t, err.Error(), "sql: database is closed")

		// Clean up
		Pool = nil
	})

	t.Run("CloseWithNilPool", func(t *testing.T) {
		Pool = nil

		// Should not panic when Pool is nil
		require.NotPanics(t, func() {
			Close()
		})
	})

	t.Run("CloseMultipleTimes", func(t *testing.T) {
		err := Initialize(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, Pool)

		// Closing multiple times should not panic
		require.NotPanics(t, func() {
			Close()
			Close()
			Close()
		})

		// Clean up
		Pool = nil
	})
}

func TestMigrations(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	t.Run("MigrationsAppliedSuccessfully", func(t *testing.T) {
		err := Initialize(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, Pool)

		// Check that goose_db_version table exists
		var tableName string
		err = Pool.QueryRow("SELECT table_name FROM information_schema.tables WHERE table_schema = 'testdb' AND table_name = 'goose_db_version'").Scan(&tableName)
		require.NoError(t, err)
		require.Equal(t, "goose_db_version", tableName)

		// Check that migrations were applied
		var version int64
		err = Pool.QueryRow("SELECT MAX(version_id) FROM goose_db_version").Scan(&version)
		require.NoError(t, err)
		require.Greater(t, version, int64(0))

		// Clean up
		Close()
		Pool = nil
	})

	t.Run("IdempotentMigrations", func(t *testing.T) {
		// First initialization
		err := Initialize(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, Pool)

		var firstVersion int64
		err = Pool.QueryRow("SELECT MAX(version_id) FROM goose_db_version").Scan(&firstVersion)
		require.NoError(t, err)

		Close()
		Pool = nil

		// Second initialization - migrations should be idempotent
		err = Initialize(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, Pool)

		var secondVersion int64
		err = Pool.QueryRow("SELECT MAX(version_id) FROM goose_db_version").Scan(&secondVersion)
		require.NoError(t, err)
		require.Equal(t, firstVersion, secondVersion)

		// Clean up
		Close()
		Pool = nil
	})
}

func TestConnectionPoolSettings(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	err := Initialize(container.URL, logger)
	require.NoError(t, err)
	require.NotNil(t, Pool)

	stats := Pool.Stats()
	require.Equal(t, 25, stats.MaxOpenConnections)

	// Note: MaxIdleConns is not directly accessible via Stats(), but we can verify it was set
	// by checking that the pool doesn't error when we try to use it

	// Clean up
	Close()
	Pool = nil
}
