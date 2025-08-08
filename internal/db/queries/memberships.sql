-- name: GetMembershipByUserIdentifierAndOrganizationIdentifier :one
SELECT *
FROM memberships
WHERE user_identifier = sqlc.arg(user_identifier)
  AND organization_identifier = sqlc.arg(organization_identifier) LIMIT 1;
