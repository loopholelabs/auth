-- name: CreateIdentity :exec
INSERT INTO identities (provider, provider_identifier, user_identifier, verified_emails, created_at)
VALUES (sqlc.arg(provider), sqlc.arg(provider_identifier), sqlc.arg(user_identifier), sqlc.arg(verified_emails),
        CURRENT_TIMESTAMP);

-- name: GetIdentityByProviderAndProviderIdentifier :one
SELECT *
FROM identities
WHERE provider = sqlc.arg(provider)
  AND provider_identifier = sqlc.arg(provider_identifier) LIMIT 1;