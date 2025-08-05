-- name: GetUser :one
SELECT *
FROM users
WHERE identifier = $1 LIMIT 1;