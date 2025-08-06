-- name: CreateOrganization :exec
INSERT INTO organizations (identifier, name, is_default, created_at)
VALUES (sqlc.arg(identifier), LOWER(sqlc.arg(name)), sqlc.arg(is_default), CURRENT_TIMESTAMP);