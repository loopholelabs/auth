-- name: CreateUser :exec
INSERT INTO users (identifier, name, primary_email, default_organization_identifier, created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(name), LOWER(sqlc.arg(primary_email)), sqlc.arg(default_organization_identifier), CURRENT_TIMESTAMP);

-- name: GetUserByIdentifier :one
SELECT *
FROM users
WHERE identifier = sqlc.arg(identifier) LIMIT 1;