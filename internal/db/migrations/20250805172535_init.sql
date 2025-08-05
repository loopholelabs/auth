-- +goose Up
-- +goose StatementBegin
-- ------------------------------------------------------------------
-- ORGANIZATIONS
-- ------------------------------------------------------------------
CREATE TABLE organizations
(
    identifier CHAR(36)     NOT NULL PRIMARY KEY DEFAULT (uuid()),
    name       VARCHAR(255) NOT NULL UNIQUE,
    is_default BOOLEAN      NOT NULL             DEFAULT TRUE,
    created_at DATETIME     NOT NULL             DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------------
-- USERS
-- ------------------------------------------------------------------
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

-- ------------------------------------------------------------------
-- IDENTITIES
-- ------------------------------------------------------------------
CREATE TABLE google_oauth_identities
(
    identifier          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_identifier     CHAR(36)     NOT NULL,
    provider_identifier VARCHAR(255) NOT NULL UNIQUE,
    verified_emails     JSON,
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_google_oauth_identities_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE github_oauth_identities
(
    identifier          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_identifier     CHAR(36)     NOT NULL,
    provider_identifier VARCHAR(255) NOT NULL UNIQUE,
    verified_emails     JSON,
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_github_oauth_identities_user_identifier_users
        FOREIGN KEY (user_identifier)
            REFERENCES users (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE magic_link_identities
(
    identifier          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_identifier     CHAR(36)     NOT NULL,
    provider_identifier VARCHAR(255) NOT NULL UNIQUE,
    verified_emails     JSON,
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_magic_link_identities_user_identifier_users
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
    identifier              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
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

    UNIQUE KEY memberships_index (user_identifier, organization_identifier)
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
    invite_hash             CHAR(60)    NOT NULL,
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
    last_generation         INT      NOT NULL,
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
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_session_revocations_session_identifier_sessions
        FOREIGN KEY (session_identifier)
            REFERENCES sessions (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE session_revalidations
(
    session_identifier CHAR(36) UNIQUE,
    generation         INT      NOT NULL,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (session_identifier, generation),

    CONSTRAINT fk_session_revalidations_session_identifier_sessions
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
    salt                    CHAR(32)    NOT NULL,
    secret_hash             CHAR(60)    NOT NULL,
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
    salt                    CHAR(32)    NOT NULL,
    secret_hash             CHAR(60)    NOT NULL,
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
    device_identifier CHAR(36),
    verifier          VARCHAR(255) NOT NULL,
    challenge         VARCHAR(255) NOT NULL,
    next_url          VARCHAR(1024),
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_google_oauth_flows_device_identifier_device_code_flows
        FOREIGN KEY (device_identifier)
            REFERENCES device_code_flows (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE github_oauth_flows
(
    identifier        CHAR(36) PRIMARY KEY  DEFAULT (uuid()),
    device_identifier CHAR(36),
    verifier          VARCHAR(255) NOT NULL,
    challenge         VARCHAR(255) NOT NULL,
    next_url          VARCHAR(1024),
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_github_oauth_flows_device_identifier_device_code_flows
        FOREIGN KEY (device_identifier)
            REFERENCES device_code_flows (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE magic_link_flows
(
    identifier        CHAR(36) PRIMARY KEY  DEFAULT (uuid()),
    device_identifier CHAR(36),
    salt              CHAR(32)     NOT NULL,
    hash              CHAR(60)     NOT NULL,
    email_address     VARCHAR(320) NOT NULL,
    ip_address        VARCHAR(64)  NOT NULL,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_magic_link_flows_device_identifier_device_code_flows
        FOREIGN KEY (device_identifier)
            REFERENCES device_code_flows (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- Configuration
-- ------------------------------------------------------------------
CREATE TABLE configuration
(
    config_key   VARCHAR(255) PRIMARY KEY,
    config_value TEXT     NOT NULL,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------------
-- Indexes
-- ------------------------------------------------------------------
-- Sessions lookup indexes
CREATE INDEX idx_sessions_user ON sessions (user_identifier);
CREATE INDEX idx_sessions_organization ON sessions (organization_identifier);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at); -- for cleanup jobs
CREATE INDEX idx_session_revalidations_session ON session_revalidations (session_identifier);

-- API Keys lookup
CREATE INDEX idx_api_keys_organization ON api_keys (organization_identifier);

-- Service Keys lookups
CREATE INDEX idx_service_keys_organization ON service_keys (organization_identifier);
CREATE INDEX idx_service_keys_user ON service_keys (user_identifier);
CREATE INDEX idx_service_keys_expires_at ON service_keys (expires_at);
-- for cleanup

-- Identity provider reverse lookups
CREATE INDEX idx_google_oauth_user ON google_oauth_identities (user_identifier);
CREATE INDEX idx_github_oauth_user ON github_oauth_identities (user_identifier);
CREATE INDEX idx_magic_link_user ON magic_link_identities (user_identifier);

-- Memberships lookup indexes
CREATE INDEX idx_memberships_user ON memberships (user_identifier);
CREATE INDEX idx_memberships_organization ON memberships (organization_identifier);

-- Invitations lookups
CREATE INDEX idx_invitations_organization ON invitations (organization_identifier);
CREATE INDEX idx_invitations_expires_at ON invitations (expires_at); -- for cleanup
CREATE INDEX idx_invitations_status ON invitations (status);
-- for pending invites queries

-- Device flows cleanup
CREATE INDEX idx_device_code_flows_created_at ON device_code_flows (created_at);

-- Flow tables cleanup
CREATE INDEX idx_google_oauth_flows_created_at ON google_oauth_flows (created_at);
CREATE INDEX idx_github_oauth_flows_created_at ON github_oauth_flows (created_at);
CREATE INDEX idx_magic_link_flows_created_at ON magic_link_flows (created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_magic_link_flows_created_at;
DROP INDEX idx_github_oauth_flows_created_at;
DROP INDEX idx_google_oauth_flows_created_at;

DROP INDEX idx_device_code_flows_created_at;

DROP INDEX idx_invitations_status;
DROP INDEX idx_invitations_expires_at;
DROP INDEX idx_invitations_organization;

DROP INDEX idx_memberships_organization;
DROP INDEX idx_memberships_user;

DROP INDEX idx_magic_link_user;
DROP INDEX idx_github_oauth_user;
DROP INDEX idx_google_oauth_user;

DROP INDEX idx_service_keys_expires_at;
DROP INDEX idx_service_keys_user;
DROP INDEX idx_service_keys_organization;

DROP INDEX idx_api_keys_organization;

DROP INDEX idx_session_revalidations_session;
DROP INDEX idx_sessions_expires_at;
DROP INDEX idx_sessions_organization;
DROP INDEX idx_sessions_user;

DROP TABLE configuration;
DROP TABLE magic_link_flows;
DROP TABLE github_oauth_flows;
DROP TABLE google_oauth_flows;
DROP TABLE device_code_flows;
DROP TABLE service_keys;
DROP TABLE api_keys;
DROP TABLE session_revalidations;
DROP TABLE session_revocations;
DROP TABLE sessions;
DROP TABLE invitations;
DROP TABLE memberships;
DROP TABLE magic_link_identities;
DROP TABLE github_oauth_identities;
DROP TABLE google_oauth_identities;
DROP TABLE users;
DROP TABLE organizations;
-- +goose StatementEnd
