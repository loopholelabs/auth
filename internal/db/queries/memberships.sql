-- name: CreateMembership :exec
INSERT INTO memberships (user_identifier, organization_identifier, role, created_at)
VALUES (sqlc.arg(user_identifier), sqlc.arg(organization_identifier), LOWER(sqlc.arg(role)), CURRENT_TIMESTAMP);

-- name: GetMembershipByUserIdentifierAndOrganizationIdentifier :one
SELECT *
FROM memberships
WHERE user_identifier = sqlc.arg(user_identifier)
  AND organization_identifier = sqlc.arg(organization_identifier) LIMIT 1;

-- name: UpdateMembershipRoleByUserIdentifier :exec
UPDATE memberships
SET role = LOWER(sqlc.arg(role))
WHERE user_identifier = sqlc.arg(user_identifier)
  AND organization_identifier = sqlc.arg(organization_identifier);
