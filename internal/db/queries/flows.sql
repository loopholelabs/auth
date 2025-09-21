-- name: CreateGithubOAuthFlow :exec
INSERT INTO github_oauth_flows (identifier, device_identifier, user_identifier, verifier, challenge, next_url,
                                created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(device_identifier), sqlc.arg(user_identifier), sqlc.arg(verifier),
        sqlc.arg(challenge), sqlc.arg(next_url), CURRENT_TIMESTAMP);

-- name: GetGithubOAuthFlowByIdentifier :one
SELECT *
FROM github_oauth_flows
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: DeleteGithubOAuthFlowByIdentifier :execrows
DELETE
FROM github_oauth_flows
WHERE identifier = sqlc.arg(identifier);

-- name: DeleteGithubOAuthFlowsBeforeCreatedAt :execrows
DELETE
FROM github_oauth_flows
WHERE created_at < sqlc.arg(created_at);

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

-- name: DeleteGoogleOAuthFlowByIdentifier :execrows
DELETE
FROM google_oauth_flows
WHERE identifier = sqlc.arg(identifier);

-- name: DeleteGoogleOAuthFlowsBeforeCreatedAt :execrows
DELETE
FROM google_oauth_flows
WHERE created_at < sqlc.arg(created_at);

-- name: DeleteAllGoogleOAuthFlows :execrows
DELETE
FROM google_oauth_flows;

-- name: CountAllGoogleOAuthFlows :one
SELECT COUNT(*)
FROM google_oauth_flows;

-- name: CreateMagicLinkFlow :exec
INSERT INTO magic_link_flows (identifier, device_identifier, user_identifier, next_url, salt, hash, email_address,
                              created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(device_identifier), sqlc.arg(user_identifier), sqlc.arg(next_url),
        sqlc.arg(salt), sqlc.arg(hash), sqlc.arg(email_address), CURRENT_TIMESTAMP);

-- name: GetMagicLinkFlowByIdentifier :one
SELECT *
FROM magic_link_flows
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: DeleteMagicLinkFlowByIdentifier :execrows
DELETE
FROM magic_link_flows
WHERE identifier = sqlc.arg(identifier);

-- name: DeleteMagicLinkFlowsBeforeCreatedAt :execrows
DELETE
FROM magic_link_flows
WHERE created_at < sqlc.arg(created_at);

-- name: DeleteAllMagicLinkFlows :execrows
DELETE
FROM magic_link_flows;

-- name: CountAllMagicLinkFlows :one
SELECT COUNT(*)
FROM magic_link_flows;

-- name: CreateDeviceCodeFlow :exec
INSERT INTO device_code_flows (identifier, code, poll, created_at)
VALUES (sqlc.arg(identifier), sqlc.arg(code), sqlc.arg(poll), CURRENT_TIMESTAMP);

-- name: GetDeviceCodeFlowByIdentifier :one
SELECT *
FROM device_code_flows
WHERE identifier = sqlc.arg(identifier) LIMIT 1;

-- name: GetDeviceCodeFlowByPoll :one
SELECT *
FROM device_code_flows
WHERE poll = sqlc.arg(poll) LIMIT 1;

-- name: GetDeviceCodeFlowByCode :one
SELECT *
FROM device_code_flows
WHERE code = sqlc.arg(code) LIMIT 1;

-- name: UpdateDeviceCodeFlowLastPollByPoll :execrows
UPDATE device_code_flows
SET last_poll = CURRENT_TIMESTAMP
WHERE poll = sqlc.arg(poll);

-- name: UpdateDeviceCodeFlowSessionIdentifierByIdentifier :execrows
UPDATE device_code_flows
SET session_identifier = sqlc.arg(session_identifier)
WHERE identifier = sqlc.arg(identifier);

-- name: DeleteDeviceCodeFlowByIdentifier :execrows
DELETE
FROM device_code_flows
WHERE identifier = sqlc.arg(identifier);

-- name: DeleteDeviceCodeFlowsBeforeCreatedAt :execrows
DELETE
FROM device_code_flows
WHERE created_at < sqlc.arg(created_at);

-- name: DeleteAllDeviceCodeFlows :execrows
DELETE
FROM device_code_flows;

-- name: CountAllDeviceCodeFlows :one
SELECT COUNT(*)
FROM device_code_flows;