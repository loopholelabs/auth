# Authentication Service Specification

---

## Section 1: Executive Summary & Core Design Principles

### 1.1 Executive Summary

The Authentication Service is a standalone, stateless microservice that provides centralized authentication and
authorization for the Loophole Labs multi-tenant SaaS platform. It manages user identities, sessions, and credentials
while maintaining complete data isolation from business logic services.

The service currently implements:

- OAuth2 authentication (GitHub, Google) with PKCE flow
- Magic Link email authentication
- Device Code flow for CLI/headless authentication
- JWT-based session management with EdDSA (Ed25519) signing
- Dynamic configuration system with database-backed settings
- Session validation with in-memory caching for revocations and invalidations

**Note**: The service is partially implemented. Core authentication flows and session management are complete, but
organization/membership management and credential management APIs are pending implementation.

### 1.2 Core Design Principles

#### 1.2.1 Data Isolation

- **Ownership Boundary**: The authentication service owns all identity, credential, and membership data
- **Internal Referential Integrity**: The authentication database uses foreign key constraints extensively (`CASCADE`
  deletes, `RESTRICT` on `users.default_organization_identifier`)
- **External Isolation**: Business services store `organization_identifier` and `user_identifier` values but have no
  foreign key constraints to authentication tables
- **Trust Model**: Services validate JWTs through the Manager's validation methods; they never query authentication tables directly
  directly

#### 1.2.2 Credential Immutability

- **Fixed Bindings**: Sessions are permanently bound to one `organization_identifier` and one `user_identifier` at
  creation
- **No Migration**: Credentials cannot be moved between organizations or users
- **Generation-Based Invalidation**: Session updates increment generation number rather than modifying the token

#### 1.2.3 Efficient Validation Through Caching

- **In-Memory Caches**: Manager maintains local caches for revocations and invalidations
- **Configurable Polling**: Poll interval configured via database configuration table
- **TTL-Based Cache**: Uses `ttlcache` library with automatic expiration matching session TTL

#### 1.2.4 Security First

- **UUID Identifiers**: All primary keys use UUIDs to prevent enumeration attacks
- **HMAC for Magic Links**: Magic link tokens use HMAC-SHA256 hashing with unique salts
- **EdDSA Signing**: JWT tokens signed with Ed25519 keys for performance and security
- **Configurable TTLs**: Session expiry configured via database (default 30 minutes)

---

## Section 2: Data Model & Current Implementation

### 2.1 Core Entities (Implemented)

#### 2.1.1 Organizations

**Table**: `organizations`

**Columns**:

- `identifier` (CHAR(36) PK): UUID, auto-generated
- `name` (VARCHAR(255)): Human-readable organization name
- `is_default` (BOOLEAN): Whether this is a user's default personal organization
- `created_at` (DATETIME): Timestamp of creation

**Current Implementation**:

- Organizations are created automatically when users sign up (default org)
- Each user has exactly one organization with `is_default = TRUE`
- No API endpoints yet for manual organization creation/management

#### 2.1.2 Users

**Table**: `users`

**Columns**:

- `identifier` (CHAR(36) PK): UUID, auto-generated
- `name` (VARCHAR(255)): User's display name
- `primary_email` (VARCHAR(255) UNIQUE): User's primary contact email (stored in lowercase)
- `default_organization_identifier` (CHAR(36) FK): User's personal default organization
- `last_seen` (DATETIME): Updated on any authenticated activity
- `created_at` (DATETIME): Account creation timestamp

**Current Implementation**:

- Users created automatically during first authentication
- Email normalization to lowercase implemented
- Foreign key to default organization with RESTRICT delete

#### 2.1.3 Identities (Unified Table)

**Table**: `identities`

**Columns**:

- `provider` (ENUM('GITHUB', 'GOOGLE', 'MAGIC')): Provider type
- `provider_identifier` (VARCHAR(255)): Provider's unique ID
- `user_identifier` (CHAR(36) FK): Links to users table
- `verified_emails` (JSON): Array of verified email addresses from provider
- `created_at` (DATETIME): When identity was linked

**Primary Key**: `(provider, provider_identifier)`

**Current Implementation**:

- Single table for all provider types (not separate tables per provider)
- Provider identifiers stored as received from provider
- Verified emails stored as JSON array

### 2.2 Access Control Entities (Schema Only)

#### 2.2.1 Memberships

**Table**: `memberships`

**Status**: Schema exists, no management APIs implemented

**Columns**:

- `user_identifier` (CHAR(36) FK): User in the membership
- `organization_identifier` (CHAR(36) FK): Organization granting access
- `role` (VARCHAR(64)): Role within organization (stored in lowercase)
- `created_at` (DATETIME): When membership was created

**Primary Key**: `(user_identifier, organization_identifier)`

#### 2.2.2 Invitations

**Table**: `invitations`

**Status**: Schema exists, no APIs implemented

**Columns**:

- `identifier` (INT UNSIGNED PK): Auto-increment
- `organization_identifier` (CHAR(36) FK): Inviting organization
- `inviter_user_identifier` (CHAR(36) FK): Admin who created invitation
- `role` (VARCHAR(64)): Proposed role for invitee
- `hash` (BINARY(32)): Hash of invitation token
- `status` (ENUM('pending', 'accepted')): Current invitation state
- `expires_at` (DATETIME): When invitation becomes invalid
- `created_at` (DATETIME): When invitation was created

### 2.3 Credential Entities

#### 2.3.1 Sessions (Fully Implemented)

**Table**: `sessions`

**Columns**:

- `identifier` (CHAR(36) PK): Session ID embedded in JWT
- `organization_identifier` (CHAR(36) FK): Fixed organization binding
- `user_identifier` (CHAR(36) FK): Fixed user binding
- `generation` (INT UNSIGNED): Current generation number for invalidation
- `expires_at` (DATETIME): Hard expiration time
- `created_at` (DATETIME): Session creation time

**Current Implementation**:

- Sessions created via `Manager.CreateSession()` and `Manager.CreateExistingSession()`
- Generation increments not yet triggered by role changes (pending membership management)
- Automatic garbage collection of expired sessions
- TTL configured via database configuration table

#### 2.3.2 Session Revocations (Fully Implemented)

**Table**: `session_revocations`

**Columns**:

- `session_identifier` (CHAR(36) PK): Session to revoke
- `expires_at` (DATETIME): When revocation record can be deleted
- `created_at` (DATETIME): When revocation occurred

**Current Implementation**:

- Created when `Manager.RevokeSession()` is called
- Expires at original session expiry + 5 second jitter
- Automatic garbage collection of expired revocations
- Cached in Manager's in-memory cache

#### 2.3.3 Session Invalidations (Fully Implemented)

**Table**: `session_invalidations`

**Columns**:

- `session_identifier` (CHAR(36)): Session needing refresh
- `generation` (INT UNSIGNED): Minimum invalid generation
- `expires_at` (DATETIME): When invalidation expires
- `created_at` (DATETIME): When invalidation was triggered

**Primary Key**: `(session_identifier, generation)`
**Unique Constraint**: `session_identifier`

**Current Implementation**:

- Support for generation-based invalidation
- Cached in Manager's in-memory cache
- Automatic garbage collection of expired invalidations

#### 2.3.4 API Keys

**Table**: `api_keys`

**Status**: Schema exists, no implementation

#### 2.3.5 Service Keys

**Table**: `service_keys`

**Status**: Schema exists, no implementation

#### 2.3.6 Machine Keys

**Table**: `machine_keys`

**Status**: Schema exists, reserved for future reporting-only keys (no auth API privileges)

### 2.4 Flow Management Entities (Fully Implemented)

#### 2.4.1 Device Code Flows

**Table**: `device_code_flows`

**Current Implementation**:

- Full CRUD operations via `device.Device` package
- 8-character user codes and UUID poll tokens
- Links to session after successful authentication

#### 2.4.2 OAuth Flow Tables

**Tables**: `google_oauth_flows`, `github_oauth_flows`

**Current Implementation**:

- PKCE flow with verifier/challenge pairs
- Automatic garbage collection of expired flows
- Links to device flow for device code authentication

#### 2.4.3 Magic Link Flows

**Table**: `magic_link_flows`

**Current Implementation**:

- HMAC-SHA256 hashing with unique salts
- Email normalization to lowercase
- Automatic garbage collection of expired flows

### 2.5 Configuration Entity (Fully Implemented)

**Table**: `configurations`

**Columns**:

- `configuration_key` (VARCHAR(255) PK): Configuration parameter name
- `configuration_value` (TEXT): Parameter value
- `updated_at` (DATETIME): Last modification time

**Currently Managed Keys**:

- `poll_interval`: How often configuration is polled (default from Options)
- `session_expiry`: Session lifetime (default from Options)
- `signing_key`: Base64-encoded Ed25519 private key
- `previous_signing_key`: Previous key for rotation support

---

## Section 3: Authentication Flows (Current Implementation)

### 3.1 Initial Sign-Up Flow (Implemented)

When a new user signs up via any provider:

1. **Provider Authentication**
    - User authenticates via Google OAuth, GitHub OAuth, or Magic Link
    - Provider returns `provider_identifier` and `verified_emails[]`

2. **Identity Lookup**
    - Query identities table for `(provider, provider_identifier)`
    - If found: use existing `user_identifier`
    - If not found: proceed to user creation

3. **User & Organization Creation** (in transaction)
    - Create user's default organization
    - Create user with reference to default organization
    - Create identity record linking provider to user
    - Organization name derived from user name or email

4. **Session Creation**
    - Issue JWT with EdDSA signature
    - Store session in database with configurable expiry
    - Return signed JWT token

### 3.2 OAuth Provider Flows (Implemented)

#### GitHub OAuth

**Endpoints**:

- `GET /v1/flows/github/login?next={url}&code={device_code}` - Initiate flow
- `GET /v1/flows/github/callback?code={code}&state={state}` - Handle callback

#### Google OAuth

**Endpoints**:

- `GET /v1/flows/google/login?next={url}&code={device_code}` - Initiate flow
- `GET /v1/flows/google/callback?code={code}&state={state}` - Handle callback

**Implementation**:

- PKCE flow with code verifier/challenge
- Optional device code integration
- Automatic user creation on first login

### 3.3 Magic Link Flow (Implemented)

**Endpoints**:

- `POST /v1/flows/magic/login` - Request magic link
- `GET /v1/flows/magic/callback?identifier={id}&token={token}` - Redeem link

**Implementation**:

- HMAC-SHA256 token generation
- Email sent via configurable mailer
- 30-minute expiry (configurable)

### 3.4 Device Code Flow (Implemented)

**Endpoints**:

- `POST /v1/flows/device/code` - Generate device code
- `POST /v1/flows/device/poll` - Poll for completion

**Implementation**:

- 8-character user code
- UUID poll token for security
- Links to OAuth/Magic flows for actual authentication

---

## Section 4: Session Management (Current Implementation)

### 4.1 JWT Token Structure

**Algorithm**: EdDSA with Ed25519 keys (not ES256)

**Token Claims**:

```json
{
  "sub": "session_identifier",
  "iss": "organization_identifier",
  "aud": "user_identifier",
  "exp": 1234571490,
  "iat": 1234567890,
  "organization_identifier": "...",
  "organization_is_default": true,
  "organization_role": "owner",
  "user_identifier": "...",
  "user_name": "...",
  "user_email": "...",
  "generation": 0
}
```

### 4.2 Session Operations (Implemented)

#### CreateSession

- Creates new session for authenticated user
- Automatically creates user/org if first login
- Returns `credential.Session` struct

#### RefreshSession

- Updates session expiry
- Checks for generation changes
- Updates user info if changed
- Returns refreshed session

#### RevokeSession

- Deletes session from database
- Creates revocation record
- Cached by Manager

#### ParseSession

- Validates JWT signature (supports key rotation)
- Returns parsed session and rotation flag
- Checks both current and previous public keys

### 4.3 Signing Key Management (Implemented)

**Configuration-Based Keys**:

- Keys stored in database configuration table
- Support for key rotation with previous key retention
- EdDSA (Ed25519) algorithm for performance

**Key Rotation** (via `Configuration.RotateSigningKey()`):

- Generates new Ed25519 key pair
- Stores previous key for grace period
- Updates configuration atomically

---

## Section 5: Session Validation (Current)

### 5.1 Validation Architecture

**Integrated into**: `pkg/manager`

**Core Components**:

- TTL-based in-memory caches for revocations and invalidations
- Background goroutine for periodic refresh
- Thread-safe with RWMutex protection
- Validation methods integrated directly into Manager

### 5.2 Caching Strategy

**Session Revocations**:

- Cached as set of revoked session IDs
- TTL matches original session expiry
- Refreshed based on poll interval

**Session Invalidations**:

- Cached as map of session ID to generation
- Used for generation-based token refresh
- TTL matches original session expiry

### 5.3 Validation Flow

```go
func (m *Manager) IsSessionValid(token string) (Session, needsRotation, error):
1. Parse JWT and validate signature
2. Check if session is revoked (cache lookup)
3. Check if generation is outdated (cache lookup)
4. Return session with rotation flag if needed

func (m *Manager) IsSessionRevoked(identifier string) bool
func (m *Manager) IsSessionInvalidated(identifier string, generation uint32) bool
```

### 5.4 Health Monitoring

- Health tracking integrated into Manager's health status
- Health check endpoint at `/v1/health` checks Manager health
- Unhealthy if cache refresh fails or configuration update fails

---

## Section 6: Current API Endpoints

### 6.1 Implemented Endpoints

#### Core Endpoints

- `GET /v1/health` - Health check
- `GET /v1/public` - Returns public keys and revocation/invalidation lists
- `POST /v1/logout` - Revoke session (cookie-based)

#### OAuth Flows

- `GET /v1/flows/github/login` - Initiate GitHub OAuth
- `GET /v1/flows/github/callback` - GitHub OAuth callback
- `GET /v1/flows/google/login` - Initiate Google OAuth
- `GET /v1/flows/google/callback` - Google OAuth callback

#### Magic Link Flow

- `POST /v1/flows/magic/login` - Request magic link
- `GET /v1/flows/magic/callback` - Redeem magic link

#### Device Flow

- `POST /v1/flows/device/code` - Generate device code
- `POST /v1/flows/device/poll` - Poll for authentication

#### Documentation

- `GET /v1/openapi.json` - OpenAPI 3.1 specification (generated by Huma v2)
- `GET /v1/docs` - Interactive API documentation (via Stoplight Elements)

### 6.2 Pending Implementation

The following endpoints are specified but not yet implemented:

#### Session Management

- `POST /v1/sessions/refresh` - Refresh session token
- `POST /v1/sessions/switch` - Switch organization
- `POST /v1/sessions/api` - Exchange API key for session
- `POST /v1/sessions/service` - Exchange service key for session
- `DELETE /v1/sessions/{identifier}` - Revoke specific session

#### Account Management

- `GET /v1/account` - Get current user
- `PATCH /v1/account` - Update user
- `DELETE /v1/account` - Delete user
- `POST /v1/account/link/{provider}` - Link additional identity
- `DELETE /v1/account/link/{provider}/{identifier}` - Unlink identity

#### Organization Management

- `GET /v1/organizations` - List user's organizations
- `POST /v1/organizations` - Create organization
- `GET /v1/organizations/{identifier}` - Get organization details
- `PATCH /v1/organizations/{identifier}` - Update organization
- `DELETE /v1/organizations/{identifier}` - Delete organization

#### Membership Management

- `GET /v1/organizations/{identifier}/members` - List members
- `PATCH /v1/organizations/{identifier}/members/{user}` - Update role
- `DELETE /v1/organizations/{identifier}/members/{user}` - Remove member

#### Invitation Management

- `GET /v1/organizations/{identifier}/invitations` - List invitations
- `POST /v1/organizations/{identifier}/invitations` - Create invitation
- `POST /v1/invitations/accept` - Accept invitation
- `POST /v1/organizations/{identifier}/invitations/{inv}/approve` - Approve acceptance
- `DELETE /v1/organizations/{identifier}/invitations/{inv}` - Cancel invitation

#### Credential Management

- `GET /v1/organizations/{identifier}/api-keys` - List API keys
- `POST /v1/organizations/{identifier}/api-keys` - Create API key
- `DELETE /v1/organizations/{identifier}/api-keys/{key}` - Revoke API key
- `GET /v1/organizations/{identifier}/service-keys` - List service keys
- `POST /v1/organizations/{identifier}/service-keys` - Create service key
- `DELETE /v1/organizations/{identifier}/service-keys/{key}` - Revoke service key

#### System Endpoints

- `GET /v1/.well-known/jwks.json` - JSON Web Key Set
- `POST /v1/admin/keys/rotate` - Admin key rotation

---

## Section 7: Package Structure

### 7.1 Internal Packages

#### internal/db

- Database connection management
- Migration handling via Goose
- SQLC-generated query code

#### internal/mailer

- Email sending abstraction
- HTML template support
- SMTP configuration

#### internal/testutils

- MySQL container setup for tests
- Mock HTTP client for testing
- Test helpers

#### internal/utils

- Generic utility functions
- Public key encoding
- Fiber app defaults

### 7.2 Public Packages

#### pkg/manager

- Core authentication logic
- Session lifecycle management
- Provider flow orchestration
- Sub-packages:
    - `configuration`: Dynamic configuration with polling
    - `flow/github`: GitHub OAuth implementation
    - `flow/google`: Google OAuth implementation
    - `flow/magic`: Magic link implementation
    - `flow/device`: Device code flow
    - `role`: Role definitions and validation

#### pkg/credential

- JWT token creation and parsing
- Session data structures
- EdDSA signing and verification

#### pkg/manager (includes validation)

- Core authentication logic
- Session validation logic
- Revocation/invalidation caching
- Health monitoring
- Configuration management

#### pkg/api/v1

- HTTP API implementation using Fiber with Huma v2
- Type-safe API with automatic OpenAPI 3.1 generation
- Request/response validation and serialization
- Struct-based Register pattern for modular endpoints
- Middleware for Fiber context access in Huma handlers

---

## Section 8: Testing Infrastructure

### 8.1 Test Patterns

**Database Tests**:

- Each test gets isolated MySQL container via `testutils.SetupMySQLContainer()`
- 5-minute timeout for container-based tests
- Automatic cleanup with `t.Cleanup()`

**Mock HTTP Client**:

- `testutils.SetupMockHTTPClient()` for external API testing
- Request verification and response mocking

**Time Mocking**:

- Package-level `now` variable for time control
- Essential for testing expiry and garbage collection

### 8.2 Test Coverage

**Well-Tested Areas**:

- Manager package core functionality
- Configuration polling and updates
- Provider flow implementations
- Session creation and validation
- Manager validation and caching logic

**Areas Needing Tests**:

- Error edge cases
- Concurrent operations

**API Testing**:

- Flow endpoints tested using `humatest.TestAPI`
- Comprehensive tests for Device, GitHub, Google, and Magic Link flows
- Tests verify status codes, error responses, and RFC 9457 compliant error details

---

## Section 9: Configuration Management

### 9.1 Database Configuration

**Dynamic Settings** (stored in configurations table):

- `poll_interval`: Configuration refresh interval
- `session_expiry`: Session lifetime
- `signing_key`: Current EdDSA private key
- `previous_signing_key`: Previous key for rotation

### 9.2 Application Configuration

**Options Structs**:

- `manager.Options`: Provider settings, mailer config, API settings
- `configuration.Options`: Poll interval, session expiry defaults
- `validator.Options`: Configuration options

### 9.3 Environment Configuration

**Database Connection**:

- MySQL 8+ required
- Connection string includes `parseTime=true` for time.Time parsing
- UTF8 character set

---

## Section 10: Security Considerations

### 10.1 Current Security Implementation

#### Cryptography

- EdDSA (Ed25519) for JWT signing
- HMAC-SHA256 for magic link tokens
- Unique salts per token
- Timing-safe comparisons

#### Session Security

- Short-lived sessions (configurable, default 30 min)
- Generation-based invalidation
- Revocation with cached blacklist
- No session state on client

#### Data Protection

- Email normalization to prevent duplicates
- UUID identifiers prevent enumeration
- Foreign key constraints ensure consistency
- Transactions for atomic operations

### 10.2 Security TODOs

- [ ] Rate limiting on authentication endpoints
- [ ] API key and service key implementation
- [ ] Audit logging for security events
- [ ] CORS policy configuration
- [ ] Content Security Policy headers

---

## Section 11: Operational Considerations

### 11.1 Garbage Collection (Implemented)

**Automatic Cleanup**:

- Expired sessions: Every `GCInterval` (1 minute)
- Expired session revocations: Every `GCInterval`
- Expired session invalidations: Via `DeleteExpiredSessionInvalidations`
- Flow cleanup: Provider-specific GC methods

### 11.2 Health Monitoring (Implemented)

**Health Checks**:

- Manager health: Database ping, configuration health, mailer health
- Validator health: Cache refresh success
- Endpoint: `GET /v1/health`

### 11.3 Performance Optimizations

**In-Memory Caching**:

- Validator maintains local caches
- TTL-based automatic expiration
- Configurable poll intervals

**Database Optimizations**:

- Prepared statements via SQLC
- Connection pooling
- Indexed lookups on identifiers

---

## Section 12: Deployment Status

### 12.1 What's Ready

- Core authentication flows (OAuth, Magic Link, Device)
- Session management and validation (integrated into Manager)
- Database schema and migrations
- Configuration management
- Manager provides validation methods for embedded use

### 12.2 What's Missing

- Organization and membership management APIs
- API key and service key implementation
- User account management endpoints
- JWKS endpoint for public key distribution
- Admin endpoints for key rotation
- Rate limiting and audit logging
- Complete API endpoint implementation

### 12.3 Next Steps for Implementation

1. **Priority 1: Core API Endpoints**
    - Session refresh endpoint
    - Account management (get/update user)
    - Organization switching

2. **Priority 2: Organization Management**
    - Organization CRUD operations
    - Membership management
    - Role-based access control

3. **Priority 3: Credential Management**
    - API key implementation
    - Service key implementation
    - Key exchange for sessions

4. **Priority 4: Production Readiness**
    - Rate limiting
    - Audit logging
    - Monitoring and metrics
    - JWKS endpoint

---

## Revision History

| Version | Date       | Author | Changes                                                |
|---------|------------|--------|--------------------------------------------------------|
| 5.1     | 2025-08-12 | -      | Updated API documentation to reflect Huma v2 migration |
| 5.0     | 2025-08-11 | -      | Updated to reflect current implementation state        |
| 4.0     | 2025-08-05 | -      | Initial specification based on finalized schema        |

---

*End of Specification*