-- +goose Up
-- +goose StatementBegin
-- ------------------------------------------------------------------
-- ORGANIZATIONS
-- ------------------------------------------------------------------
CREATE TABLE organizations
(
    identifier CHAR(36)     NOT NULL PRIMARY KEY DEFAULT (uuid()),
    name       VARCHAR(255) NOT NULL,
    is_default BOOLEAN      NOT NULL             DEFAULT TRUE,
    created_at DATETIME     NOT NULL             DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------------
-- USERS
-- ------------------------------------------------------------------
CREATE TABLE users
(
    identifier                      CHAR(36)     NOT NULL PRIMARY KEY DEFAULT (uuid()),
    name                            VARCHAR(255) NOT NULL,
    primary_email                   VARCHAR(255) NOT NULL UNIQUE,
    default_organization_identifier CHAR(36)     NOT NULL,
    last_seen                       DATETIME     NOT NULL             DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at                      DATETIME     NOT NULL             DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_users_default_org
        FOREIGN KEY (default_organization_identifier)
            REFERENCES organizations (identifier)
            ON DELETE RESTRICT -- prevent silent cascade-delete
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- USER IDENTITIES
-- ------------------------------------------------------------------
CREATE TABLE identities
(
    provider            ENUM('GITHUB', 'GOOGLE', 'MAGIC') NOT NULL,
    provider_identifier VARCHAR(255) NOT NULL,
    user_identifier     CHAR(36)     NOT NULL,
    verified_emails     JSON         NOT NULL,
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (provider, provider_identifier),

    CONSTRAINT fk_google_oauth_identities_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- Organization Memberships
-- ------------------------------------------------------------------
CREATE TABLE memberships
(
    user_identifier         CHAR(36)    NOT NULL,
    organization_identifier CHAR(36)    NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    created_at              DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_memberships_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    CONSTRAINT fk_memberships_organization_identifier_organizations
        FOREIGN KEY (organization_identifier)
            REFERENCES organizations (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    PRIMARY KEY memberships_index (user_identifier, organization_identifier)
);

-- ------------------------------------------------------------------
-- Organization Invitations
-- ------------------------------------------------------------------
CREATE TABLE invitations
(
    identifier              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    organization_identifier CHAR(36)    NOT NULL,
    inviter_user_identifier CHAR(36)    NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    hash                    BINARY(60)    NOT NULL,
    status                  ENUM('pending', 'accepted') NOT NULL DEFAULT 'pending',
    expires_at              DATETIME    NOT NULL,
    created_at              DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_invitations_organization_identifier_organizations
        FOREIGN KEY (organization_identifier)
            REFERENCES organizations (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    CONSTRAINT fk_invitations_inviter_user_identifier_users
        FOREIGN KEY (inviter_user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- Sessions
-- ------------------------------------------------------------------
CREATE TABLE sessions
(
    identifier              CHAR(36) PRIMARY KEY DEFAULT (uuid()),
    organization_identifier CHAR(36) NOT NULL,
    user_identifier         CHAR(36) NOT NULL,
    generation              INT UNSIGNED NOT NULL,
    expires_at              DATETIME NOT NULL,
    created_at              DATETIME NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sessions_organization_identifier_organizations
        FOREIGN KEY (organization_identifier)
            REFERENCES organizations (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    CONSTRAINT fk_sessions_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE session_revocations
(
    session_identifier CHAR(36) PRIMARY KEY,
    expires_at         DATETIME NOT NULL,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE session_invalidations
(
    session_identifier CHAR(36) NOT NULL UNIQUE,
    generation         INT UNSIGNED     NOT NULL,
    expires_at         DATETIME NOT NULL,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (session_identifier, generation),

    CONSTRAINT fk_session_invalidations_session_identifier_sessions
        FOREIGN KEY (session_identifier)
            REFERENCES sessions (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- API Keys
-- ------------------------------------------------------------------
CREATE TABLE api_keys
(
    identifier              CHAR(36) PRIMARY KEY DEFAULT (uuid()),
    salt                    CHAR(36)    NOT NULL,
    hash                    BINARY(60)    NOT NULL,
    organization_identifier CHAR(36)    NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    created_at              DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_api_keys_organization_identifier_organizations
        FOREIGN KEY (organization_identifier)
            REFERENCES organizations (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- Service Keys
-- ------------------------------------------------------------------
CREATE TABLE service_keys
(
    identifier              CHAR(36) PRIMARY KEY DEFAULT (uuid()),
    salt                    CHAR(36)    NOT NULL,
    hash                    BINARY(60)    NOT NULL,
    organization_identifier CHAR(36)    NOT NULL,
    user_identifier         CHAR(36)    NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    resource_ids            JSON,
    expires_at              DATETIME    NOT NULL,
    created_at              DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_service_keys_organization_identifier_organizations
        FOREIGN KEY (organization_identifier)
            REFERENCES organizations (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    CONSTRAINT fk_service_keys_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- Flows
-- ------------------------------------------------------------------
CREATE TABLE device_code_flows
(
    identifier         CHAR(36) PRIMARY KEY DEFAULT (uuid()),
    session_identifier CHAR(36),
    code               CHAR(8)  NOT NULL,
    poll               CHAR(36) NOT NULL,
    last_poll          DATETIME NOT NULL,
    created_at         DATETIME NOT NULL    DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_device_code_flows_session_identifier_sessions
        FOREIGN KEY (session_identifier)
            REFERENCES sessions (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE google_oauth_flows
(
    identifier        CHAR(36) PRIMARY KEY  DEFAULT (uuid()),
    verifier          VARCHAR(255) NOT NULL,
    challenge         VARCHAR(255) NOT NULL,
    device_identifier CHAR(36),
    user_identifier   char(36),
    next_url          VARCHAR(1024),
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_google_oauth_flows_device_identifier_device_code_flows
        FOREIGN KEY (device_identifier)
            REFERENCES device_code_flows (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    CONSTRAINT fk_google_oauth_flows_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE github_oauth_flows
(
    identifier        CHAR(36) PRIMARY KEY  DEFAULT (uuid()),
    verifier          VARCHAR(255) NOT NULL,
    challenge         VARCHAR(255) NOT NULL,
    device_identifier CHAR(36),
    user_identifier   char(36),
    next_url          VARCHAR(1024),
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_github_oauth_flows_device_identifier_device_code_flows
        FOREIGN KEY (device_identifier)
            REFERENCES device_code_flows (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    CONSTRAINT fk_github_oauth_flows_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE magic_link_flows
(
    identifier        CHAR(36) PRIMARY KEY  DEFAULT (uuid()),
    salt              CHAR(36)     NOT NULL,
    hash              BINARY(60)     NOT NULL,
    email_address     VARCHAR(320) NOT NULL,
    device_identifier CHAR(36),
    user_identifier   CHAR(36),
    next_url          VARCHAR(1024),
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_magic_link_flows_device_identifier_device_code_flows
        FOREIGN KEY (device_identifier)
            REFERENCES device_code_flows (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE,

    CONSTRAINT fk_magic_link_flows_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- Configuration
-- ------------------------------------------------------------------
CREATE TABLE configurations
(
    configuration_key   VARCHAR(255) PRIMARY KEY,
    configuration_value TEXT     NOT NULL,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE configuration;
DROP TABLE magic_link_flows;
DROP TABLE github_oauth_flows;
DROP TABLE google_oauth_flows;
DROP TABLE device_code_flows;
DROP TABLE service_keys;
DROP TABLE api_keys;
DROP TABLE session_invalidations;
DROP TABLE session_revocations;
DROP TABLE sessions;
DROP TABLE invitations;
DROP TABLE memberships;
DROP TABLE identities;
DROP TABLE users;
DROP TABLE organizations;
-- +goose StatementEnd
