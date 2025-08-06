//SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"embed"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/loopholelabs/logging/types"
	"github.com/pressly/goose/v3"
)

//go:generate go tool github.com/sqlc-dev/sqlc/cmd/sqlc generate --file sqlc.yaml

var (
	ErrMissingParseTimeOption       = errors.New("missing parse time option")
	ErrMissingMultiStatementsOption = errors.New("missing multi statements option")
	ErrMissingLocationOption        = errors.New("missing location option")
)

//go:embed migrations/*.sql
var Migrations embed.FS

const (
	parseTimeOption       = "parseTime=true"
	multiStatementsOption = "multiStatements=true"
	locationOption        = "loc=UTC"
)

var Pool *sql.DB

type gooseLogger struct {
	logger types.Logger
}

func (l *gooseLogger) Fatalf(format string, v ...any) {
	l.logger.Error().Msgf(strings.TrimSpace(format), v...)
}

func (l *gooseLogger) Printf(format string, v ...any) {
	l.logger.Info().Msgf(strings.TrimSpace(format), v...)
}

func Initialize(url string, logger types.Logger) error {

	l := logger.SubLogger("DATABASE")

	var err error

	if !strings.Contains(url, parseTimeOption) {
		return fmt.Errorf("invalid database url: %w", ErrMissingParseTimeOption)
	}

	if !strings.Contains(url, multiStatementsOption) {
		return fmt.Errorf("invalid database url: %w", ErrMissingMultiStatementsOption)
	}

	if !strings.Contains(url, locationOption) {
		return fmt.Errorf("invalid database url: %w", ErrMissingLocationOption)
	}

	Pool, err = sql.Open("mysql", url)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	Pool.SetMaxOpenConns(25)
	Pool.SetMaxIdleConns(25)
	Pool.SetConnMaxLifetime(3 * time.Minute)

	err = Pool.Ping()
	if err != nil {
		Pool.Close()
		Pool = nil
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Run database migrations.
	goose.SetBaseFS(Migrations)
	goose.SetLogger(&gooseLogger{logger: l})

	err = goose.SetDialect("mysql")
	if err != nil {
		Pool.Close()
		Pool = nil
		return fmt.Errorf("failed to set database dialect: %w", err)
	}

	err = goose.Up(Pool, "migrations")
	if err != nil {
		Pool.Close()
		Pool = nil
		return fmt.Errorf("failed apply database migrations: %w", err)
	}

	return nil
}

func Close() {
	if Pool != nil {
		_ = Pool.Close()
	}
}
