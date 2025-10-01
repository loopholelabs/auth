//SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type PostgreSQLContainer struct {
	container testcontainers.Container
	URL       string
}

func SetupPostgreSQLContainer(t testing.TB) *PostgreSQLContainer {
	t.Helper()
	_t, ok := t.(*testing.T)
	if ok {
		_t.Parallel()
	}

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_PASSWORD": "testpassword",
			"POSTGRES_DB":       "testdb",
			"POSTGRES_USER":     "postgres",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start PostgreSQL container")

	host, err := container.Host(t.Context())
	require.NoError(t, err, "failed to get container host")

	port, err := container.MappedPort(t.Context(), "5432")
	require.NoError(t, err, "failed to get container port")

	hostPort := net.JoinHostPort(host, port.Port())
	url := fmt.Sprintf("postgres://postgres:testpassword@%s/testdb?sslmode=disable", hostPort)

	postgresContainer := &PostgreSQLContainer{
		container: container,
		URL:       url,
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	// Wait for PostgreSQL to be truly ready
	maxRetries := 30
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		config, err := pgxpool.ParseConfig(url)
		if err == nil {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err == nil {
				lastErr = pool.Ping(ctx)
				pool.Close()
				cancel()
				if lastErr == nil {
					break
				}
			} else {
				lastErr = err
			}
			cancel()
		} else {
			lastErr = err
		}
		if i == maxRetries-1 {
			require.NoError(t, lastErr, "PostgreSQL container not ready after %d retries", maxRetries)
		}
		time.Sleep(1 * time.Second)
	}

	return postgresContainer
}
