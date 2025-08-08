-- name: CreateSession :exec
INSERT INTO sessions (identifier, organization_identifier, user_identifier, last_generation, expires_at, created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(organization_identifier), sqlc.arg(user_identifier), sqlc.arg(last_generation),
        sqlc.arg(expires_at), CURRENT_TIMESTAMP);

-- name: UpdateSessionExpiryByIdentifier :exec
UPDATE sessions
SET expires_at = sqlc.arg(expires_at)
WHERE identifier = sqlc.arg(identifier);

-- name: UpdateSessionLastGenerationByIdentifier :exec
UPDATE sessions
SET last_generation = sqlc.arg(last_generation)
WHERE identifier = sqlc.arg(identifier);

-- name: GetSessionByIdentifier :one
SELECT *
FROM sessions
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: DeleteSessionByIdentifier :exec
DELETE
FROM sessions
WHERE identifier = sqlc.arg(identifier);

-- name: DeleteExpiredSessions :execrows
DELETE
FROM sessions
WHERE expires_at <= NOW();