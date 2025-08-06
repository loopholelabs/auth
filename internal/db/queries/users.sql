-- name: CreateUser :exec
INSERT INTO users (identifier, primary_email, default_organization, created_at)
VALUES (sqlc.arg(identifier), LOWER(sqlc.arg(primary_email)), sqlc.arg(default_organization), CURRENT_TIMESTAMP);