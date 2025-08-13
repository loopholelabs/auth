-- name: CreateOrganization :exec
INSERT INTO organizations (identifier, name, is_default, created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(name), sqlc.arg(is_default), CURRENT_TIMESTAMP);

-- name: GetOrganizationByIdentifier :one
SELECT *
FROM organizations
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: GetOrganizationsForUserIdentifier :many
SELECT o.*,
       m.role       as membership_role,
       m.created_at AS membership_created_at
FROM memberships m
         INNER JOIN organizations o ON m.organization_identifier = o.identifier
WHERE m.user_identifier = sqlc.arg(user_identifier)
ORDER BY o.created_at DESC;