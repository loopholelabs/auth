-- +goose Up
-- +goose StatementBegin
ALTER TABLE device_code_flows 
    ALTER COLUMN last_poll DROP NOT NULL,
    ALTER COLUMN last_poll DROP DEFAULT,
    ALTER COLUMN last_poll SET DEFAULT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE device_code_flows 
    ALTER COLUMN last_poll SET NOT NULL,
    ALTER COLUMN last_poll SET DEFAULT CURRENT_TIMESTAMP;
-- +goose StatementEnd