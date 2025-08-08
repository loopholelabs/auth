-- name: CreateSessionRevocation :exec
INSERT INTO session_revocations (session_identifier, expires_at, created_at)
VALUES (sqlc.arg(session_identifier), sqlc.arg(expires_at), CURRENT_TIMESTAMP);

-- name: DeleteExpiredSessionRevocations :execrows
DELETE
FROM session_revocations
WHERE expires_at <= NOW();

-- name: GetAllSessionRevocations :many
SELECT *
FROM session_revocations;