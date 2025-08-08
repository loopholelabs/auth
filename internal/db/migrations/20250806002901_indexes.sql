-- +goose Up
-- +goose StatementBegin
-- ------------------------------------------------------------------
-- Indexes
-- ------------------------------------------------------------------
-- Sessions lookup indexes
CREATE INDEX idx_sessions_user ON sessions (user_identifier);
CREATE INDEX idx_sessions_organization ON sessions (organization_identifier);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at); -- for cleanup jobs
CREATE INDEX idx_session_invalidations_session ON session_invalidations (session_identifier);

-- API Keys lookup
CREATE INDEX idx_api_keys_organization ON api_keys (organization_identifier);

-- Service Keys lookups
CREATE INDEX idx_service_keys_organization ON service_keys (organization_identifier);
CREATE INDEX idx_service_keys_user ON service_keys (user_identifier);
CREATE INDEX idx_service_keys_expires_at ON service_keys (expires_at);
-- for cleanup

-- Identity provider reverse lookups
CREATE INDEX idx_identities_user ON identities (user_identifier);

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

DROP INDEX idx_session_invalidation_session;
DROP INDEX idx_sessions_expires_at;
DROP INDEX idx_sessions_organization;
DROP INDEX idx_sessions_user;
-- +goose StatementEnd
