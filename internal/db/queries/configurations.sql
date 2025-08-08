-- name: SetConfiguration :exec
INSERT INTO configurations (configuration_key, configuration_value, updated_at)
VALUES (sqlc.arg(configuration_key), sqlc.arg(configuration_value), CURRENT_TIMESTAMP) ON DUPLICATE KEY
UPDATE
    configuration_value =
VALUES (configuration_value), updated_at = CURRENT_TIMESTAMP;

-- name: GetConfigurationByKey :one
SELECT *
FROM configurations
WHERE configuration_key = sqlc.arg(configuration_key) LIMIT 1;

-- name: GetAllConfigurations :many
SELECT *
FROM configurations;