//SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL Driver
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type MySQLContainer struct {
	container testcontainers.Container
	URL       string
}

func SetupMySQLContainer(t testing.TB) *MySQLContainer {
	t.Helper()

	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "mysql:8.0",
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": "testpassword",
			"MYSQL_DATABASE":      "testdb",
		},
		WaitingFor: wait.ForLog("ready for connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start MySQL container")

	host, err := container.Host(ctx)
	require.NoError(t, err, "failed to get container host")

	port, err := container.MappedPort(ctx, "3306")
	require.NoError(t, err, "failed to get container port")

	url := fmt.Sprintf("root:testpassword@tcp(%s:%s)/testdb?parseTime=true&multiStatements=true&loc=UTC", host, port.Port())

	mysqlContainer := &MySQLContainer{
		container: container,
		URL:       url,
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	// Wait for MySQL to be truly ready
	maxRetries := 30
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		db, err := sql.Open("mysql", url)
		if err == nil {
			lastErr = db.PingContext(t.Context())
			_ = db.Close()
			if lastErr == nil {
				break
			}
		} else {
			lastErr = err
		}
		if i == maxRetries-1 {
			require.NoError(t, lastErr, "MySQL container not ready after %d retries", maxRetries)
		}
		time.Sleep(1 * time.Second)
	}

	return mysqlContainer
}
