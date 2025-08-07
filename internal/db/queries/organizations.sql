-- name: CreateOrganization :exec
INSERT INTO organizations (identifier, name, is_default, created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(name), sqlc.arg(is_default), CURRENT_TIMESTAMP);

-- name: GetOrganizationByIdentifier :one
SELECT *
FROM organizations
WHERE identifier = sqlc.arg(identifier) LIMIT 1;