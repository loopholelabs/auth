-- +goose Up
-- +goose StatementBegin
CREATE TABLE organizations
(
    identifier CHAR(36)     NOT NULL PRIMARY KEY DEFAULT (uuid()),
    name       VARCHAR(255) NOT NULL UNIQUE,
    is_default BOOLEAN      NOT NULL             DEFAULT TRUE,
    created_at DATETIME     NOT NULL             DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users
(
    identifier           CHAR(36)     NOT NULL PRIMARY KEY DEFAULT (uuid()),
    primary_email        VARCHAR(255) NOT NULL UNIQUE,
    default_organization CHAR(36)     NOT NULL,
    last_seen            DATETIME     NOT NULL             DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at           DATETIME     NOT NULL             DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_users_default_org
        FOREIGN KEY (default_organization)
            REFERENCES organizations (identifier)
            ON DELETE RESTRICT -- prevent silent cascade-delete
            ON UPDATE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
DROP TABLE organizations;
-- +goose StatementEnd
