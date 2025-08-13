-- name: CreateSessionInvalidation :exec
INSERT INTO session_invalidations (session_identifier, generation, expires_at, created_at)
VALUES (sqlc.arg(session_identifier), sqlc.arg(generation), sqlc.arg(expires_at), CURRENT_TIMESTAMP);

-- name: GetAllSessionInvalidations :many
SELECT *
FROM session_invalidations;

-- name: DeleteExpiredSessionInvalidations :execrows
DELETE
FROM session_invalidations
WHERE expires_at <= NOW();

-- name: CreateSessionInvalidationsFromSessionByUserIdentifier :execrows
INSERT INTO session_invalidations (session_identifier, generation, expires_at)
SELECT identifier, generation, expires_at
FROM sessions
WHERE user_identifier = sqlc.arg(user_identifier);