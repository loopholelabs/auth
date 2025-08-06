-- name: CreateGithubOAuthFlow :exec
INSERT INTO github_oauth_flows (identifier, device_identifier, user_identifier, verifier, challenge, next_url,
                                created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(device_identifier), sqlc.arg(user_identifier), sqlc.arg(verifier),
        sqlc.arg(challenge), sqlc.arg(next_url), CURRENT_TIMESTAMP);

-- name: GetGithubOAuthFlowByIdentifier :one
SELECT *
FROM github_oauth_flows
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: DeleteGithubOAuthFlowByIdentifier :exec
DELETE
FROM github_oauth_flows
WHERE identifier = ?;

-- name: DeleteGithubOAuthFlowsBeforeTime :execrows
DELETE
FROM github_oauth_flows
WHERE created_at < ?;

-- name: DeleteAllGithubOAuthFlows :execrows
DELETE
FROM github_oauth_flows;

-- name: CountAllGithubOAuthFlows :one
SELECT COUNT(*)
FROM github_oauth_flows;

-- name: CreateGoogleOAuthFlow :exec
INSERT INTO google_oauth_flows (identifier, device_identifier, user_identifier, verifier, challenge, next_url,
                                created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(device_identifier), sqlc.arg(user_identifier), sqlc.arg(verifier),
        sqlc.arg(challenge), sqlc.arg(next_url), CURRENT_TIMESTAMP);

-- name: GetGoogleOAuthFlowByIdentifier :one
SELECT *
FROM google_oauth_flows
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: DeleteGoogleOAuthFlowByIdentifier :exec
DELETE
FROM google_oauth_flows
WHERE identifier = ?;

-- name: DeleteGoogleOAuthFlowsBeforeTime :execrows
DELETE
FROM google_oauth_flows
WHERE created_at < ?;

-- name: DeleteAllGoogleOAuthFlows :execrows
DELETE
FROM google_oauth_flows;

-- name: CountAllGoogleOAuthFlows :one
SELECT COUNT(*)
FROM google_oauth_flows;