-- name: CreateSession :exec
INSERT INTO sessions (identifier, organization_identifier, user_identifier, generation, expires_at, created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(organization_identifier), sqlc.arg(user_identifier), sqlc.arg(generation),
        sqlc.arg(expires_at), CURRENT_TIMESTAMP);

-- name: UpdateSessionExpiryByIdentifier :execrows
UPDATE sessions
SET expires_at = sqlc.arg(expires_at)
WHERE identifier = sqlc.arg(identifier);

-- name: UpdateSessionGenerationByIdentifier :execrows
UPDATE sessions
SET generation = sqlc.arg(generation)
WHERE identifier = sqlc.arg(identifier);

-- name: GetSessionByIdentifier :one
SELECT *
FROM sessions
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: DeleteSessionByIdentifier :execrows
DELETE
FROM sessions
WHERE identifier = sqlc.arg(identifier);

-- name: DeleteExpiredSessions :execrows
DELETE
FROM sessions
WHERE expires_at <= NOW();