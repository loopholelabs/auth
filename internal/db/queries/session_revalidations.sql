-- name: CreateSessionRevalidation :exec
INSERT INTO session_revalidations (session_identifier, generation, expires_at, created_at)
VALUES (sqlc.arg(session_identifier), sqlc.arg(generation), sqlc.arg(expires_at), CURRENT_TIMESTAMP);

-- name: GetAllSessionRevalidations :many
SELECT *
FROM session_revalidations;

-- name: DeleteExpiredSessionRevalidations :execrows
DELETE
FROM session_revalidations
WHERE expires_at <= NOW();