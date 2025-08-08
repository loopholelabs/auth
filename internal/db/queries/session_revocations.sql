-- name: CreateSessionRevocation :exec
INSERT INTO session_revocations (session_identifier, created_at)
VALUES (sqlc.arg(session_identifier), CURRENT_TIMESTAMP);

-- name: DeleteSessionRevocationsBeforeCreatedAt :execrows
DELETE
FROM session_revocations
WHERE created_at < sqlc.arg(created_at);
