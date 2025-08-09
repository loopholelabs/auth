# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a standalone authentication service for Loophole Labs that implements a multi-tenant SaaS authentication system. It provides OAuth2 (GitHub, Google), Magic Link authentication, and comprehensive session/credential management with a MySQL 8+ backend. The service maintains complete data isolation from business logic services and uses JWT-based authentication.

## Quick Start

### Prerequisites
- Go 1.21+ (required for testing framework features)
- Docker (required for test containers)
- Make (for build automation)

### First Time Setup
```bash
# Install dependencies
go mod download

# Generate code (SQLC, Swagger)
make generate

# Run tests
make test
```

## Essential Commands

### Build and Generate
```bash
# Generate all code (sqlc, swagger docs)
make generate

# Run after modifying:
# - internal/db/queries/*.sql files (regenerates SQL query code)
# - internal/db/migrations/*.sql files (database schema)
# - API annotations (regenerates swagger docs)
```

### Testing
```bash
# Run all tests (uses 5min timeout for container-based tests)
make test

# Run specific tests
make test-specific TEST_ARGS="./pkg/manager/..."

# Run full test suite with appropriate timeout
go test -v ./... -timeout 5m

# Run single test with shorter timeout (if you know it's fast)
go test -v ./pkg/manager/configuration/ -run TestKeyString -timeout 30s

# Run tests without cache
go test -count=1 -v ./path/to/package -timeout 5m
```

**Important Test Timeout Considerations**:
- **Default timeout**: Use 5 minutes (`-timeout 5m`) for most test runs as tests spin up MySQL containers
- **Container startup**: Each test with database access creates a new MySQL container (4-10 seconds startup)
- **Test isolation**: Each test gets its own container to prevent state pollution
- **Quick tests**: For non-database tests (like `TestKeyString`), 30s timeout is sufficient
- **Debugging**: If tests timeout, run them individually to identify slow tests

### Linting
```bash
# Run linter with auto-fix
make lint

# Note: Always sets GOOS=linux for consistency
```

## Architecture Overview

### Core Package Structure

**Authentication Flow System** (`pkg/manager/flow/`)
- Each provider (GitHub, Google, Magic) implements the flow interface
- PKCE flow for OAuth2 providers with code verifier/challenge
- Flows are stored in database with automatic garbage collection
- Time-based cleanup using `now` variable for test mocking

**Session Management** (`pkg/manager/`)
- `CreateSession` is the central authentication endpoint
- Creates users, organizations, and identities in a transaction
- Sessions expire after configurable duration (default 30 min)
- Role-based access with organization memberships

**Configuration System** (`pkg/manager/configuration/`)
- Database-backed dynamic configuration
- Polling-based updates without restart
- Thread-safe access with RWMutex
- Supports session expiry and poll interval configuration

### Database Layer

**Schema Management**
- Migrations in `internal/db/migrations/` using Goose
- SQLC for type-safe query generation from `internal/db/queries/`
- MySQL with serializable transaction isolation for critical operations

**Key Tables**
- `users`: Primary user accounts with unique email constraint
- `identities`: Provider-specific identities (GitHub, Google, Magic)
- `organizations`: User organizations with default organization
- `sessions`: Active user sessions with generation tracking
- `configurations`: Dynamic runtime configuration

**Important Constraints**
- `users.primary_email` has UNIQUE constraint
- Foreign keys enforce referential integrity
- Identity primary key is composite: (provider, provider_identifier)

### Testing Infrastructure

**Test Patterns**
- Use `testutils.SetupMySQLContainer(t)` for database tests
- Each test gets isolated MySQL container to avoid state pollution
- Use `t.Context()` for context passing
- Use `t.Cleanup()` for resource cleanup
- Use `require` package for assertions (fail-fast)
- Use `assert` package for non-critical assertions

**Mock HTTP Client**
- Use `testutils.SetupMockHTTPClient(t)` for testing external API calls
- Configure responses with `SetResponse()` or `SetResponseForRequest()`
- Verify requests with `AssertRequestMade()` and `GetRequests()`

**Test Organization**
- Group related tests using subtests with `t.Run()`
- Create new containers only in subtests that need database access
- Use table-driven tests for similar test cases

**Time Mocking**
- Package variables like `now = time.Now` allow time mocking in tests
- Essential for testing expiry, garbage collection, and time-based features

### Error Handling

**Error Wrapping Pattern**
```go
errors.Join(ErrCreatingSession, err)
```
- All packages define sentinel errors (e.g., `ErrCreatingSession`)
- Use `errors.Join` for error context
- Check `sql.ErrNoRows` for not-found cases
- Check `sql.ErrTxDone` before logging rollback errors

### Transaction Management

**Pattern for Critical Operations**
```go
tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
defer func() {
    if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
        logger.Error().Err(err).Msg("failed to rollback")
    }
}()
// ... operations ...
err = tx.Commit()
```

### SQL Queries

**Upsert Pattern**
When modifying queries in `internal/db/queries/`, use MySQL's ON DUPLICATE KEY UPDATE:
```sql
-- name: SetConfiguration :exec
INSERT INTO configurations (configuration_key, configuration_value, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP)
ON DUPLICATE KEY UPDATE
    configuration_value = VALUES(configuration_value),
    updated_at = CURRENT_TIMESTAMP;
```

### Provider Implementation

New authentication providers must:
1. Implement flow creation and completion methods
2. Include garbage collection for expired flows
3. Return `flow.Data` with all required fields except `UserName`. 
4. Add provider enum to database identities table
5. Handle PKCE for OAuth2 flows

### Security Considerations

- Magic link tokens use bcrypt hashing
- OAuth2 flows use PKCE for security
- Sessions have generation tracking for revocation
- All provider identifiers are validated before use
- Transactions use serializable isolation for consistency

## Common Development Tasks

### Adding a New Configuration Key

1. Add the key constant to `pkg/manager/configuration/configuration.go`:
```go
const MyNewKey Key = "my_new_key"
```

2. Add field and getter to Configuration struct:
```go
type Configuration struct {
    // ... existing fields ...
    myNewValue string
}

func (c *Configuration) MyNewValue() string {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.myNewValue
}
```

3. Update `initialize()` and `update()` methods to handle the new key

4. Add tests in `configuration_test.go`

### Modifying Database Schema

1. Create new migration file:
```bash
goose -dir internal/db/migrations create my_change sql
```

2. Write migration SQL (up and down)

3. Run migration:
```bash
goose -dir internal/db/migrations mysql "user:pass@tcp(localhost:3306)/db" up
```

4. Update queries in `internal/db/queries/` if needed

5. Regenerate SQLC code:
```bash
make generate
```

### Adding a New Authentication Provider

1. Create package in `pkg/manager/flow/newprovider/`

2. Implement required interfaces:
   - Flow creation and completion
   - Garbage collection
   - Return proper `flow.Data`

3. Add provider enum to database schema

4. Update `Manager` in `pkg/manager/manager.go`

5. Add comprehensive tests following existing patterns

## Debugging Tips

### Test Failures

**Container Issues**
- Check Docker is running: `docker ps`
- Clean up orphaned containers: `docker container prune`
- Check Docker resources: `docker system df`

**Database Connection Issues**
- Verify MySQL container is ready (check logs)
- Ensure migrations ran successfully
- Check connection string format

**Timeout Issues**
- Increase test timeout: `-timeout 60s`
- Run tests individually to isolate slow tests
- Check for deadlocks or infinite loops

### Common Errors

**"Duplicate entry for key"**
- Use UPSERT pattern (INSERT ... ON DUPLICATE KEY UPDATE)
- Check for unique constraint violations

**"sql: database is closed"**
- Ensure proper cleanup order in tests
- Check defer statements order
- Verify context cancellation

## Performance Considerations

- Configuration polling runs in background goroutine
- Use appropriate poll intervals (default 5s)
- Container-per-test adds overhead but ensures isolation
- Consider using test caching during development: `go test -count=1`
- Database queries use prepared statements via SQLC

## Code Style Guidelines

- Follow Go idioms and conventions
- Use meaningful variable names
- Keep functions small and focused
- Document exported types and functions
- Use structured logging with zerolog
- Handle errors explicitly, don't ignore them
- Use defer for cleanup operations
- Prefer early returns to reduce nesting

## Important Files

- `docs/SPECIFICATION.md`: Complete system specification
- `Makefile`: Build and test automation
- `sqlc.yaml`: SQLC configuration
- `.goose.yaml`: Database migration configuration
- `internal/db/migrations/`: Database schema files
- `internal/db/queries/`: SQL query definitions
- `internal/testutils/`: Testing utilities
- `pkg/manager/`: Core authentication logic