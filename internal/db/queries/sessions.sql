-- name: CreateSession :exec
INSERT INTO sessions (identifier, organization_identifier, user_identifier, last_generation, expires_at, created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(organization_identifier), sqlc.arg(user_identifier), sqlc.arg(last_generation),
        sqlc.arg(expires_at), CURRENT_TIMESTAMP);

-- name: GetSessionByIdentifier :one
SELECT *
FROM sessions
WHERE identifier = sqlc.arg(identifier) LIMIT 1;