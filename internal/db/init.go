//SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db/generated"
)

//go:generate go tool sqlc generate --file sqlc.yaml

const (
	pingTimeout  = time.Second * 30
	maxLifetime  = time.Minute * 3
	maxOpenConns = 25
)

//go:embed migrations/*.sql
var Migrations embed.FS

type DB struct {
	logger  types.Logger
	Queries *generated.Queries
	Pool    *pgxpool.Pool
	DB      *sql.DB // sql.DB interface for compatibility
}

type gooseLogger struct {
	logger types.Logger
}

func (l *gooseLogger) Fatalf(format string, v ...any) {
	l.logger.Error().Msgf(strings.TrimSpace(format), v...)
}

func (l *gooseLogger) Printf(format string, v ...any) {
	l.logger.Debug().Msgf(strings.TrimSpace(format), v...)
}

func New(url string, logger types.Logger) (*DB, error) {
	l := logger.SubLogger("DATABASE")

	// Parse PostgreSQL connection config
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database url: %w", err)
	}

	// Set connection pool settings
	config.MaxConns = maxOpenConns
	config.MinConns = 2
	config.MaxConnLifetime = maxLifetime

	// Create pool
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Ping with timeout
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	
	err = pool.Ping(ctx)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create sql.DB for goose migrations
	sqlDB := stdlib.OpenDBFromPool(pool)

	// Set Goose Logger
	goose.SetBaseFS(Migrations)
	goose.SetLogger(&gooseLogger{logger: l.SubLogger("GOOSE")})

	err = goose.SetDialect("postgres")
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to set database dialect: %w", err)
	}

	err = goose.Up(sqlDB, "migrations")
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed apply database migrations: %w", err)
	}

	return &DB{
		logger:  l,
		Queries: generated.New(pool),
		Pool:    pool,
		DB:      sqlDB,
	}, nil
}

func (db *DB) Close() error {
	// Close both the sql.DB and the pool
	// The sql.DB is used for migrations, the pool for queries
	if db.DB != nil {
		if err := db.DB.Close(); err != nil {
			return err
		}
	}
	if db.Pool != nil {
		db.Pool.Close()
	}
	return nil
}

// BeginTx starts a new pgx transaction with the given options
func (db *DB) BeginTx(ctx context.Context, opts sql.TxOptions) (pgx.Tx, error) {
	// Convert SQL isolation level to pgx isolation level
	var pgxOpts pgx.TxOptions
	switch opts.Isolation {
	case sql.LevelReadCommitted:
		pgxOpts.IsoLevel = pgx.ReadCommitted
	case sql.LevelRepeatableRead:
		pgxOpts.IsoLevel = pgx.RepeatableRead
	case sql.LevelSerializable:
		pgxOpts.IsoLevel = pgx.Serializable
	default:
		pgxOpts.IsoLevel = pgx.ReadCommitted
	}

	if opts.ReadOnly {
		pgxOpts.AccessMode = pgx.ReadOnly
	} else {
		pgxOpts.AccessMode = pgx.ReadWrite
	}

	return db.Pool.BeginTx(ctx, pgxOpts)
}
