-- +goose Up
-- +goose StatementBegin
-- ------------------------------------------------------------------
-- ORGANIZATIONS
-- ------------------------------------------------------------------
CREATE TABLE organizations
(
    identifier UUID         NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(255) NOT NULL,
    is_default BOOLEAN      NOT NULL             DEFAULT TRUE,
    created_at TIMESTAMP    NOT NULL             DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------------
-- USERS
-- ------------------------------------------------------------------
CREATE TABLE users
(
    identifier                      UUID         NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    name                            VARCHAR(255) NOT NULL,
    primary_email                   VARCHAR(255) NOT NULL UNIQUE,
    default_organization_identifier UUID         NOT NULL,
    last_login                      TIMESTAMP    NOT NULL             DEFAULT CURRENT_TIMESTAMP,
    created_at                      TIMESTAMP    NOT NULL             DEFAULT CURRENT_TIMESTAMP,

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
    provider            VARCHAR(10) NOT NULL CHECK (provider IN ('GITHUB', 'GOOGLE', 'MAGIC')),
    provider_identifier VARCHAR(255) NOT NULL,
    user_identifier     UUID     NOT NULL,
    verified_emails     JSONB    NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    user_identifier         UUID        NOT NULL,
    organization_identifier UUID        NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    created_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

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

    PRIMARY KEY (user_identifier, organization_identifier)
);

-- ------------------------------------------------------------------
-- Organization Invitations
-- ------------------------------------------------------------------
CREATE TABLE invitations
(
    identifier              SERIAL PRIMARY KEY,
    organization_identifier UUID        NOT NULL,
    inviter_user_identifier UUID        NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    hash                    BYTEA       NOT NULL CHECK (octet_length(hash) = 32),
    status                  VARCHAR(10) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted')),
    expires_at              TIMESTAMP   NOT NULL,
    created_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    identifier              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_identifier UUID      NOT NULL,
    user_identifier         UUID      NOT NULL,
    generation              INTEGER   NOT NULL,
    expires_at              TIMESTAMP NOT NULL,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    session_identifier UUID PRIMARY KEY,
    expires_at         TIMESTAMP NOT NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE session_invalidations
(
    session_identifier UUID      NOT NULL,
    generation         INTEGER   NOT NULL,
    expires_at         TIMESTAMP NOT NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    identifier              CHAR(12) PRIMARY KEY,
    salt                    UUID        NOT NULL,
    hash                    BYTEA       NOT NULL CHECK (octet_length(hash) = 32),
    organization_identifier UUID        NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    created_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    identifier              CHAR(12) PRIMARY KEY,
    salt                    UUID        NOT NULL,
    hash                    BYTEA       NOT NULL CHECK (octet_length(hash) = 32),
    organization_identifier UUID        NOT NULL,
    user_identifier         UUID        NOT NULL,
    role                    VARCHAR(64) NOT NULL,
    resource_ids            JSONB,
    expires_at              TIMESTAMP   NOT NULL,
    created_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
-- Machine Keys
-- ------------------------------------------------------------------
CREATE TABLE machine_keys
(
    identifier              CHAR(12) PRIMARY KEY,
    salt                    UUID        NOT NULL,
    hash                    BYTEA       NOT NULL CHECK (octet_length(hash) = 32),
    organization_identifier UUID        NOT NULL,
    kind                    VARCHAR(64) NOT NULL,
    created_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_machine_keys_organization_identifier_organizations
        FOREIGN KEY (organization_identifier)
            REFERENCES organizations (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

-- ------------------------------------------------------------------
-- Flows
-- ------------------------------------------------------------------
CREATE TABLE device_code_flows
(
    identifier         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_identifier UUID UNIQUE,
    code               VARCHAR(8)  NOT NULL UNIQUE,
    poll               UUID        NOT NULL UNIQUE,
    last_poll          TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at         TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_device_code_flows_session_identifier_sessions
        FOREIGN KEY (session_identifier)
            REFERENCES sessions (identifier)
            ON DELETE CASCADE
            ON UPDATE CASCADE
);

CREATE TABLE google_oauth_flows
(
    identifier        UUID PRIMARY KEY   DEFAULT gen_random_uuid(),
    verifier          VARCHAR(255)  NOT NULL,
    challenge         VARCHAR(255)  NOT NULL,
    device_identifier UUID,
    user_identifier   UUID,
    next_url          VARCHAR(1024) NOT NULL,
    created_at        TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    identifier        UUID PRIMARY KEY   DEFAULT gen_random_uuid(),
    verifier          VARCHAR(255)  NOT NULL,
    challenge         VARCHAR(255)  NOT NULL,
    device_identifier UUID,
    user_identifier   UUID,
    next_url          VARCHAR(1024) NOT NULL,
    created_at        TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    identifier        UUID PRIMARY KEY   DEFAULT gen_random_uuid(),
    salt              UUID          NOT NULL,
    hash              BYTEA         NOT NULL CHECK (octet_length(hash) = 32),
    email_address     VARCHAR(320)  NOT NULL,
    device_identifier UUID,
    user_identifier   UUID,
    next_url          VARCHAR(1024) NOT NULL,
    created_at        TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

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
    configuration_value TEXT      NOT NULL,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE configurations;
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