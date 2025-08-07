//SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db/generated"
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

type DB struct {
	logger  types.Logger
	Queries *generated.Queries
	DB      *sql.DB
}

type gooseLogger struct {
	logger types.Logger
}

func (l *gooseLogger) Fatalf(format string, v ...any) {
	l.logger.Error().Msgf(strings.TrimSpace(format), v...)
}

func (l *gooseLogger) Printf(format string, v ...any) {
	l.logger.Info().Msgf(strings.TrimSpace(format), v...)
}

type mysqlLogger struct {
	logger types.Logger
}

func (l *mysqlLogger) Print(v ...any) {
	l.logger.Info().Msg(fmt.Sprint(v...))
}

func New(url string, logger types.Logger) (*DB, error) {
	if !strings.Contains(url, parseTimeOption) {
		return nil, fmt.Errorf("invalid database url: %w", ErrMissingParseTimeOption)
	}

	if !strings.Contains(url, multiStatementsOption) {
		return nil, fmt.Errorf("invalid database url: %w", ErrMissingMultiStatementsOption)
	}

	if !strings.Contains(url, locationOption) {
		return nil, fmt.Errorf("invalid database url: %w", ErrMissingLocationOption)
	}

	l := logger.SubLogger("DATABASE")

	// Set MySQL Logger
	err := mysql.SetLogger(&mysqlLogger{logger: l.SubLogger("MYSQL")})
	if err != nil {
		return nil, fmt.Errorf("failed to set mysql logger: %w", err)
	}

	// Set Goose Logger
	goose.SetBaseFS(Migrations)
	goose.SetLogger(&gooseLogger{logger: l.SubLogger("GOOSE")})

	db, err := sql.Open("mysql", url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(3 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	err = goose.SetDialect("mysql")
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set database dialect: %w", err)
	}

	err = goose.Up(db, "migrations")
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed apply database migrations: %w", err)
	}

	return &DB{
		logger:  l,
		Queries: generated.New(db),
		DB:      db,
	}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}
