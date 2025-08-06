//SPDX-License-Identifier: Apache-2.0

package db

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/loopholelabs/logging"

	"github.com/loopholelabs/auth/internal/testutils"
)

func TestInitialize(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	t.Run("SuccessfulInitialization", func(t *testing.T) {
		db, err := New(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, db)

		// Verify connection pool settings
		stats := db.DB.Stats()
		require.Equal(t, 25, stats.MaxOpenConnections)

		// Verify we can query the database
		var result int
		err = db.DB.QueryRow("SELECT 1").Scan(&result)
		require.NoError(t, err)
		require.Equal(t, 1, result)

		// Clean up for next test
		err = db.Close()
		require.NoError(t, err)
	})

	t.Run("MissingParseTimeOption", func(t *testing.T) {
		invalidURL := "root:testpassword@tcp(localhost:3306)/testdb?multiStatements=true&loc=UTC"
		db, err := New(invalidURL, logger)
		require.ErrorIs(t, err, ErrMissingParseTimeOption)
		require.Nil(t, db)
	})

	t.Run("MissingMultiStatementsOption", func(t *testing.T) {
		invalidURL := "root:testpassword@tcp(localhost:3306)/testdb?parseTime=true&loc=UTC"
		db, err := New(invalidURL, logger)
		require.ErrorIs(t, err, ErrMissingMultiStatementsOption)
		require.Nil(t, db)
	})

	t.Run("MissingLocationOption", func(t *testing.T) {
		invalidURL := "root:testpassword@tcp(localhost:3306)/testdb?parseTime=true&multiStatements=true"
		db, err := New(invalidURL, logger)
		require.ErrorIs(t, err, ErrMissingLocationOption)
		require.Nil(t, db)
	})

	t.Run("InvalidDatabaseURL", func(t *testing.T) {
		invalidURL := "invalid://url?parseTime=true&multiStatements=true&loc=UTC"
		db, err := New(invalidURL, logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to connect to database")
		require.Nil(t, db)
	})

	t.Run("UnreachableDatabase", func(t *testing.T) {
		unreachableURL := "root:wrongpassword@tcp(localhost:9999)/testdb?parseTime=true&multiStatements=true&loc=UTC"
		db, err := New(unreachableURL, logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to ping database")
		require.Nil(t, db)
	})
}

func TestClose(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	t.Run("CloseValidConnection", func(t *testing.T) {
		db, err := New(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, db)

		// Close should not panic
		require.NotPanics(t, func() {
			err = db.Close()
			require.NoError(t, err)
		})

		// Verify connection is closed
		err = db.DB.Ping()
		require.Error(t, err)
		require.Contains(t, err.Error(), "sql: database is closed")
	})

	t.Run("CloseMultipleTimes", func(t *testing.T) {
		db, err := New(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, db)

		// First close should work
		err = db.Close()
		require.NoError(t, err)

		// Closing again should still work (sql.DB.Close is idempotent)
		require.NotPanics(t, func() {
			err = db.Close()
			// sql.DB.Close returns nil even when already closed
			require.NoError(t, err)
		})
	})
}

func TestMigrations(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	t.Run("MigrationsAppliedSuccessfully", func(t *testing.T) {
		db, err := New(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, db)

		// Check that goose_db_version table exists
		var tableName string
		err = db.DB.QueryRow("SELECT table_name FROM information_schema.tables WHERE table_schema = 'testdb' AND table_name = 'goose_db_version'").Scan(&tableName)
		require.NoError(t, err)
		require.Equal(t, "goose_db_version", tableName)

		// Check that migrations were applied
		var version int64
		err = db.DB.QueryRow("SELECT MAX(version_id) FROM goose_db_version").Scan(&version)
		require.NoError(t, err)
		require.Positive(t, version)

		// Clean up
		err = db.Close()
		require.NoError(t, err)
	})

	t.Run("IdempotentMigrations", func(t *testing.T) {
		// First initialization
		db1, err := New(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, db1)

		var firstVersion int64
		err = db1.DB.QueryRow("SELECT MAX(version_id) FROM goose_db_version").Scan(&firstVersion)
		require.NoError(t, err)

		err = db1.Close()
		require.NoError(t, err)

		// Second initialization - migrations should be idempotent
		db2, err := New(container.URL, logger)
		require.NoError(t, err)
		require.NotNil(t, db2)

		var secondVersion int64
		err = db2.DB.QueryRow("SELECT MAX(version_id) FROM goose_db_version").Scan(&secondVersion)
		require.NoError(t, err)
		require.Equal(t, firstVersion, secondVersion)

		// Clean up
		err = db2.Close()
		require.NoError(t, err)
	})
}

func TestConnectionPoolSettings(t *testing.T) {
	container := testutils.SetupMySQLContainer(t)
	logger := logging.Test(t, logging.Zerolog, "test")

	db, err := New(container.URL, logger)
	require.NoError(t, err)
	require.NotNil(t, db)

	stats := db.DB.Stats()
	require.Equal(t, 25, stats.MaxOpenConnections)

	// Note: MaxIdleConns is not directly accessible via Stats(), but we can verify it was set
	// by checking that the pool doesn't error when we try to use it

	// Clean up
	err = db.Close()
	require.NoError(t, err)
}
