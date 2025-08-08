# Authentication Service Specification

---

## Section 1: Executive Summary & Core Design Principles

### 1.1 Executive Summary

The Authentication Service is a standalone, stateless microservice that provides centralized authentication and
authorization for a multi-tenant SaaS platform. It issues and validates various credential types (Sessions, API Keys,
Service Keys) while maintaining complete data isolation from business logic services.

The service exposes REST/JSON endpoints under `/v1`, maintains its own MySQL 8+ database, and provides client libraries
for credential validation. All inter-service communication uses bearer tokens validated through embedded validator
libraries, ensuring no service directly accesses the authentication database.

### 1.2 Core Design Principles

#### 1.2.1 Data Isolation

- **Ownership Boundary**: The authentication service owns all identity, credential, and membership data
- **Internal Referential Integrity**: The authentication database uses foreign key constraints extensively to maintain
  data consistency (`CASCADE` deletes, `RESTRICT` on `user.default_organization`, etc.)
- **External Isolation**: Business services store `organization_identifier` and `user_identifier` values but have no
  foreign key constraints to authentication tables - they trust the JWT claims
- **Trust Model**: Services validate JWTs through the validator library; they never query authentication tables directly

#### 1.2.2 Referential Integrity Within Authentication Service

- **Cascade Deletes**: Most foreign keys use `ON DELETE CASCADE` to cleanly remove related data
- **Prevent Orphaning**: `users.default_organization` uses `ON DELETE RESTRICT` to prevent accidental organization
  deletion
- **Consistent Updates**: All foreign keys use `ON UPDATE CASCADE` to maintain consistency
- **Guaranteed Relationships**: Foreign keys ensure sessions always have valid users/orgs, memberships always reference
  real entities, etc.

#### 1.2.3 Credential Immutability

- **Fixed Bindings**: All credentials are permanently bound to one `organization_identifier` and one `user_identifier`at
  creation (enforced by foreign keys)
- **No Migration**: Credentials cannot be moved between organizations or users
- **Invalidation over Mutation**: Changes trigger invalidation (new token generation) rather than modification

#### 1.2.4 Efficient Validation Through Caching

- **In-Memory Lookups**: Validators cache revocation and invalidation data locally
- **Periodic Polling**: Configurable refresh cycle balances freshness with database load
- **Silent Rotation**: Generation mismatches trigger automatic token refresh without failing requests
- **Zero-Downtime Updates**: Role changes and permission updates apply within a configurable amount of time

#### 1.2.5 Security First

- **UUID Identifiers**: All primary keys use UUIDs to prevent enumeration attacks
- **Bcrypt Hashing**: All secrets use bcrypt with appropriate salt rounds
- **Short TTLs**: Session tokens expire in a configurable amount of time, requiring regular refresh
- **Explicit Revocation**: Support for immediate credential invalidation

#### 1.2.6 Explicit State Management

- **No Automatic Linking**: Email addresses never automatically link accounts
- **No Soft Deletes**: Deleted records are removed, not marked inactive
- **Clear Workflows**: Each state transition has explicit API endpoints

### 1.3 System Boundaries

#### 1.3.1 What the Authentication Service Owns

- User identity and authentication flows
- Organization membership and roles
- Credential issuance and validation
- Session management and refresh
- JWKS and key rotation

#### 1.3.2 What the Authentication Service Does NOT Own

- Business logic or domain models
- User profiles beyond authentication needs
- Application-specific permissions (beyond organization-level roles)
- Resource-level access control
- Audit logs for business operations

### 1.4 Field Normalization Rules

All string fields must be normalized before storage:

- **Email addresses**: Always converted to lowercase before storage or comparison
- **Organization names**: Always converted to lowercase before storage or comparison
- **Role names**: Always converted to lowercase before storage or comparison
- **Provider identifiers**: Stored as-provided (case-sensitive, provider-dependent)

---

## Section 2: Data Model & Entity Relationships

### 2.1 Core Entities

#### 2.1.1 Organizations

**Purpose**: Represents isolated tenants in the multi-tenant system. Every user has exactly one default organization
that is created when they sign up.

**Columns**:

- `identifier` (CHAR(36) PK): UUID, auto-generated
- `name` (VARCHAR(255) UNIQUE): Human-readable organization name, **stored in lowercase**
- `is_default` (BOOLEAN): Whether this is a user's default personal organization
- `created_at` (DATETIME): Timestamp of creation

**Business Rules**:

- Organization names must be globally unique (case-insensitive, stored lowercase)
- Each user has exactly one organization with `is_default = TRUE` (their personal organization)
- Default organizations are created automatically during user signup
- Organizations cannot be renamed once created (to prevent confusion in audit trails)
- Default organizations cannot be deleted while user exists (enforced by FK RESTRICT)
- Non-default organizations can be deleted, cascading to all related data

#### 2.1.2 Users

**Purpose**: Core identity that can belong to multiple organizations.

**Columns**:

- `identifier` (CHAR(36) PK): UUID, auto-generated
- `primary_email` (VARCHAR(255) UNIQUE): User's primary contact email, **stored in lowercase**
- `default_organization` (CHAR(36) FK): User's personal default organization
- `last_seen` (DATETIME): Updated on any authenticated activity
- `created_at` (DATETIME): Account creation timestamp

**Business Rules**:

- `primary_email` is normalized to lowercase before storage
- `primary_email` is mutable after creation (email can be selected from the verified emails stored by identities)
- `default_organization` points to user's personal organization (1:1 relationship)
- User deletion cascades to all identities, memberships, and sessions
- `last_seen` updates automatically via `ON UPDATE CURRENT_TIMESTAMP`
- Cannot delete organization if it's a user's default (FK RESTRICT protects this)

#### 2.1.3 Identity Providers

Three tables with identical structure:

- `google_oauth_identities`
- `github_oauth_identities`
- `magic_link_identities`

**Columns** (each table):

- `identifier` (INT UNSIGNED PK): Auto-increment
- `user_identifier` (CHAR(36) FK): Links to users table
- `provider_identifier` (VARCHAR(255) UNIQUE): Provider's unique ID
    - Google: OAuth `sub` claim (case-sensitive)
    - GitHub: User ID (case-sensitive)
    - Magic Link: Email address (**stored in lowercase**)
- `verified_emails` (JSON): Array of verified email addresses from provider, **stored in lowercase**
- `created_at` (DATETIME): When identity was linked

**Business Rules**:

- `provider_identifier` must be unique per table (no two users can link same Google account)
- One user can have multiple identities of same type (e.g., multiple Google accounts)
- `verified_emails` stores only emails the provider has confirmed, normalized to lowercase
- No automatic account linking based on email matches
- For magic links, `provider_identifier` is the lowercase email address
- Expiry for temporary authentication flows computed as `created_at + <configurable duration>`

### 2.2 Access Control Entities

#### 2.2.1 Memberships

**Purpose**: Links users to organizations with specific roles.

**Columns**:

- `identifier` (INT UNSIGNED PK): Auto-increment
- `user_identifier` (CHAR(36) FK): User in the membership
- `organization_identifier` (CHAR(36) FK): Organization granting access
- `role` (VARCHAR(64)): Role within organization, **stored in lowercase** (e.g., 'owner', 'admin', 'member')
- `created_at` (DATETIME): When membership was created

**Unique Constraint**: `(user_identifier, organization_identifier)` - one membership per user-organization pair

**Business Rules**:

- Existence of membership record = active membership (no state field needed)
- First user creating an organization gets 'owner' role automatically
- User always has 'owner' role in their default organization
- Roles are normalized to lowercase before storage
- Role changes require admin/owner privileges
- Deletion of membership revokes all sessions for that user-organization combination

#### 2.2.2 Invitations

**Purpose**: Tracks pending organization invitations.

**Columns**:

- `identifier` (INT UNSIGNED PK): Auto-increment
- `organization_identifier` (CHAR(36) FK): Inviting organization
- `inviter_user_identifier` (CHAR(36) FK): Admin who created invitation
- `role` (VARCHAR(64)): Proposed role for invitee, **stored in lowercase**
- `invite_hash` (CHAR(60)): Bcrypt hash of invitation token
- `status` (ENUM('pending', 'accepted')): Current invitation state
- `expires_at` (DATETIME): When invitation becomes invalid
- `created_at` (DATETIME): When invitation was created

**Business Rules**:

- Token in invitation URL is hashed before storage (never store plaintext)
- Roles are normalized to lowercase before storage
- Status flow: 'pending' → 'accepted' → deleted (when membership created)
- Expired invitations should be deleted by cleanup job
- User accepting invitation can be existing user or create new account
- If inviter is deleted, their invitations are cascade deleted

### 2.3 Credential Entities

#### 2.3.1 Sessions

**Purpose**: Short-lived JWT-based credentials for interactive use.

**Columns**:

- `identifier` (CHAR(36) PK): Session ID embedded in JWT
- `organization_identifier` (CHAR(36) FK): Fixed organization binding
- `user_identifier` (CHAR(36) FK): Fixed user binding
- `last_generation` (INT): Current generation number for invalidation
- `expires_at` (DATETIME): Hard expiration time
- `created_at` (DATETIME): Session creation time

**Business Rules**:

- Sessions are immutable except for `last_generation`
- Generation increments trigger JWT refresh (user gets new token)
- TTL typically 60 minutes from creation (read from configuration table)
- Cannot be transferred between users or organizations
- Expired sessions should be deleted by cleanup job

#### 2.3.2 Session Revocations

**Purpose**: Immediately invalidate specific sessions.

**Columns**:

- `session_identifier` (CHAR(36) PK, FK)`: Session to revoke
- `created_at` (DATETIME): When revocation occurred

**Business Rules**:

- Presence in this table = session is revoked (401 response)
- Validators poll this table every `revocation_poll_seconds` (typically 60 seconds)
- Revoked session IDs are cached in-memory by validators for fast lookup
- When validator's in-memory cache contains a session ID, return 401 immediately
- Records can be deleted after session natural expiration
- Expiry computed as: related session's `expires_at` + 24 hours (grace period)

#### 2.3.3 Session Invalidations

**Purpose**: Track generation changes requiring token refresh.

**Columns**:

- `session_identifier` (CHAR(36) FK): Session needing refresh
- `generation` (INT): New generation number
- `created_at` (DATETIME): When invalidation was triggered

**Primary Key**: `(session_identifier, generation)` - supports multiple generation updates

**Business Rules**:

- Validators poll this table every `invalidation_poll_seconds` (typically 60 seconds)
- Validator caches `session_identifier -> latest_generation` mapping in memory
- When validator detects generation mismatch (JWT generation < cached generation):
    - Silently calls `/v1/sessions/refresh` on behalf of the user
    - Returns new JWT to the client in a special header
    - Proceeds with the API call using the new session context (updated role, permissions)
- Client libraries should transparently handle session rotation
- Records expire when related session expires
- Multiple generations can be invalidated concurrently

#### 2.3.4 API Keys

**Purpose**: Long-lived credentials for programmatic access at organization level.

**Columns**:

- `identifier` (CHAR(36) PK): Key ID
- `salt` (CHAR(32)): Random salt for this key
- `secret_hash` (CHAR(60)): Bcrypt hash of actual secret
- `organization_identifier` (CHAR(36) FK): Bound organization
- `role` (VARCHAR(64)): Permissions level, **stored in lowercase**
- `created_at` (DATETIME): When key was issued

**Business Rules**:

- No user association (organization-level only, no `user_identifier`)
- No expiration (revoke explicitly when needed)
- Roles are normalized to lowercase before storage
- Secret shown once at creation, never retrievable
- Format: `org_[identifier]_[random_secret]`
- Can be exchanged for short-lived JWT ("API Session") for performance
- API Session TTL read from configuration table (typically 15 minutes)

#### 2.3.5 Service Keys

**Purpose**: Scoped, time-limited credentials for service-to-service communication.

**Columns**:

- `identifier` (CHAR(36) PK): Key ID
- `salt` (CHAR(32)): Random salt
- `secret_hash` (CHAR(60)): Bcrypt hash
- `organization_identifier` (CHAR(36) FK): Bound organization
- `user_identifier` (CHAR(36) FK): Associated user (for audit)
- `role` (VARCHAR(64)): Permissions level, **stored in lowercase**
- `resource_ids` (JSON): Optional array of specific resource IDs
- `expires_at` (DATETIME): Hard expiration
- `created_at` (DATETIME): When issued

**Business Rules**:

- Must have both organization and user binding
- Automatic expiration without cleanup needed
- Roles are normalized to lowercase before storage
- `resource_ids` allows fine-grained access control
- Format: `svc_[identifier]_[random_secret]`
- Can be exchanged for short-lived JWT ("Service Session")
- Service Session TTL read from configuration table (typically 15 minutes)

### 2.4 Flow Management Entities

#### 2.4.1 Device Code Flows

**Purpose**: Manages device authorization flows (e.g., CLI, TV apps).

**Columns**:

- `identifier` (CHAR(36) PK): Flow ID
- `session_identifier` (CHAR(36) FK, nullable): Created session after success
- `code` (CHAR(8)): User-visible code for device
- `poll` (CHAR(36)): Secret for device to poll with
- `last_poll` (DATETIME): Rate limiting for polling
- `created_at` (DATETIME): Flow start time

**Business Rules**:

- Code shown to user on device (e.g., "ABCD-1234")
- Device polls with `poll` token every 5 seconds
- Flow expires after `created_at + 15 minutes`
- Once authorized, `session_identifier` is populated
- Expired flows deleted by cleanup job

#### 2.4.2 OAuth Flow Tables

**Tables**: `google_oauth_flows`, `github_oauth_flows`

**Columns** (each table):

- `identifier` (CHAR(36) PK): Flow ID
- `device_identifier` (CHAR(36) FK, nullable): Links to device flow if applicable
- `verifier` (VARCHAR(255)): PKCE code verifier
- `challenge` (VARCHAR(255)): PKCE code challenge
- `next_url` (VARCHAR(1024), nullable): Post-authentication redirect
- `created_at` (DATETIME): Flow start time

**Business Rules**:

- PKCE (Proof Key for Code Exchange) prevents authorization code interception
- Flows expire after `created_at + 10 minutes`
- Verifier stored temporarily, deleted after use
- Challenge sent to OAuth provider, verified on callback

#### 2.4.3 Magic Link Flows

**Purpose**: Email-based authentication flows.

**Columns**:

- `identifier` (CHAR(36) PK): Flow ID
- `device_identifier` (CHAR(36) FK, nullable): Links to device flow
- `salt` (CHAR(32)): Salt for token hash
- `hash` (CHAR(60)): Bcrypt hash of magic link token
- `email_address` (VARCHAR(320)): Target email, **stored in lowercase**
- `ip_address` (VARCHAR(64)): Request origin for security
- `created_at` (DATETIME): Flow start time

**Business Rules**:

- Email addresses normalized to lowercase before storage
- Token in email link is never stored (only hash)
- Links expire after `created_at + 30 minutes`
- IP address logged for abuse detection
- One-time use (deleted after successful authentication)

### 2.5 Configuration Entity

#### 2.5.1 Configuration

**Purpose**: Key-value store for service configuration.

**Columns**:

- `config_key` (VARCHAR(255) PK): Configuration parameter name
- `config_value` (TEXT): Parameter value (may be JSON)
- `updated_at` (DATETIME): Last modification time

**Standard Keys**:

```
session_ttl_seconds           | 3600    | Interactive session lifetime
api_session_ttl_seconds       | 900     | API key → JWT exchange lifetime  
service_session_ttl_seconds   | 900     | Service key → JWT exchange lifetime
revocation_poll_seconds       | 60      | How often validators check revocations
validator_poll_seconds        | 300     | How often validators refresh config
es256_private_key            | [PEM]   | Signing key for JWTs
es256_public_key             | [PEM]   | Verification key for JWTs
jwks                         | [JSON]  | Published JSON Web Key Set
config_version               | 1       | Increments on key rotation
device_flow_ttl_seconds      | 900     | Device code flow timeout
oauth_flow_ttl_seconds       | 600     | OAuth PKCE flow timeout
magic_link_ttl_seconds       | 1800    | Magic link validity period
```

---

## Section 3: Authentication Flows

### 3.1 Initial Sign-Up Flow

When a new user signs up, the service creates their identity ecosystem:

1. **Provider Authentication**
    - User authenticates via Google OAuth, GitHub OAuth, or Magic Link
    - Provider returns `provider_identifier` and `verified_emails[]`

2. **Identity Lookup**
    - Query provider's identity table for `provider_identifier`
    - If found: use existing `user_identifier`
    - If not found: proceed to user creation

3. **User & Organization Creation** (for new users)
   ```sql
   BEGIN TRANSACTION;
   
   -- Create user's default organization
   INSERT INTO organizations (identifier, name, is_default) 
   VALUES (uuid(), LOWER(?email_username_part), TRUE);
   
   -- Create user with default organization
   INSERT INTO users (identifier, primary_email, default_organization)
   VALUES (uuid(), LOWER(?email), ?organization_identifier);
   
   -- Create provider identity
   INSERT INTO [provider]_identities (user_identifier, provider_identifier, verified_emails)
   VALUES (?user_identifier, ?provider_id, JSON_ARRAY(LOWER(?emails)));
   
   -- Create owner membership in default organization
   INSERT INTO memberships (user_identifier, organization_identifier, role)
   VALUES (?user_identifier, ?organization_identifier, 'owner');
   
   COMMIT;
   ```

4. **Session Creation**
    - Issue JWT with `organization_identifier` = user's default organization
    - Record in sessions table with 60-minute expiry

### 3.2 Sign-In Flow (Existing User)

1. **Provider Authentication**
    - User authenticates via chosen provider
    - Provider returns `provider_identifier`

2. **Identity Resolution**
   ```sql
   SELECT user_identifier FROM [provider]_identities 
   WHERE provider_identifier = ?provider_identifier;
   ```

3. **Session Creation**
    - Determine target organization (default or previously selected)
    - Verify active membership exists
    - Issue JWT and record session

4. **Activity Tracking**
   ```sql
   UPDATE users SET last_seen = CURRENT_TIMESTAMP 
   WHERE identifier = ?user_identifier;
   ```

### 3.3 OAuth Provider Flow (Google/GitHub)

1. **Initiate OAuth**
   ```
   POST /v1/oauth/google/authorize
   {
     "redirect_uri": "https://app.example.com/callback",
     "device_flow_id": null  // optional, for device pairing
   }
   ```

2. **Create PKCE Flow**
    - Generate cryptographically random `verifier` (43-128 chars)
    - Calculate `challenge` = BASE64URL(SHA256(verifier))
    - Store in `google_oauth_flows` table
    - Redirect to provider with challenge

3. **Handle Callback**
   ```
   GET /v1/oauth/google/callback?code=...&state=...
   ```
    - Retrieve flow by state parameter
    - Exchange code for tokens using stored verifier
    - Get user info from provider
    - Create/retrieve user as in sign-up flow
    - Delete flow record
    - Redirect to `next_url` with session token

### 3.4 Magic Link Flow

1. **Request Magic Link**
   ```
   POST /v1/authentication/magic-link
   {
     "email": "user@example.com"
   }
   ```

2. **Create Flow**
    - Generate cryptographically secure token (32 bytes)
    - Bcrypt hash the token
    - Store in `magic_link_flows` with normalized email
    - Send email with link containing flow ID and plaintext token

3. **Redeem Magic Link**
   ```
   POST /v1/authentication/magic-link/redeem
   {
     "flow_id": "...",
     "token": "..."
   }
   ```
    - Retrieve flow record
    - Verify token against stored hash
    - Check expiry (30 minutes)
    - Create/retrieve user with email as `provider_identifier`
    - Delete flow record
    - Issue session

### 3.5 Device Code Flow

1. **Initiate Device Flow**
   ```
   POST /v1/authentication/device
   ```
   Response:
   ```json
   {
     "device_code": "ABCD-1234",
     "verification_url": "https://app.example.com/device",
     "poll_token": "uuid-for-polling",
     "expires_in": 900
   }
   ```

2. **User Authorization**
    - User visits URL, enters code
    - System validates code
    - User signs in via any provider
    - System links session to device flow

3. **Device Polling**
   ```
   POST /v1/authentication/device/poll
   {
     "poll_token": "uuid-for-polling"
   }
   ```
    - Returns `pending` or session details
    - Rate limited to 1 request per 5 seconds
    - Expires after 15 minutes

### 3.6 Identity Linking

**Add Additional Provider** (requires existing session)

```
POST /v1/account/link/google
Authorization: Bearer [session_jwt]
```

1. Initiate OAuth flow with special flag
2. After provider authentication, check if `provider_identifier` already exists
3. If exists: error (already linked to another user)
4. If not: add to current user's identities
5. Update `verified_emails` in identity record

**Security**: Step-up authentication may be required (recent password/2FA).

---

## Section 4: Organization & Membership Management

### 4.1 Organization Creation

Beyond the default organization created at sign-up, users can create additional organizations:

```
POST /v1/organizations
Authorization: Bearer [session_jwt]
{
  "name": "acme-corp"
}
```

**Process**:

1. Normalize name to lowercase
2. Check name uniqueness
3. Create organization with `is_default = FALSE`
4. Create membership with creator as 'owner'
5. Return organization details

### 4.2 Invitation Workflow

#### 4.2.1 Create Invitation

```
POST /v1/organizations/{organization_identifier}/invitations
Authorization: Bearer [session_jwt]
{
  "role": "member"
}
```

**Process**:

1. Verify sender has 'admin' or 'owner' role
2. Generate secure random token
3. Bcrypt hash the token
4. Store invitation with 7-day expiry
5. Return invitation URL with plaintext token

#### 4.2.2 Accept Invitation

```
POST /v1/invitations/accept
{
  "token": "invitation_token_here"
}
```

**Process**:

1. Hash provided token
2. Find matching invitation where `status = 'pending'`
3. Check expiry
4. If user not authenticated: redirect to sign-up/sign-in
5. Update invitation `status = 'accepted'`
6. Return pending acceptance message

#### 4.2.3 Approve Accepted Invitation

```
POST /v1/organizations/{organization_identifier}/invitations/{invite_id}/approve
Authorization: Bearer [session_jwt]
```

**Process**:

1. Verify approver has 'admin' or 'owner' role
2. Verify invitation `status = 'accepted'`
3. Create membership with invited user and specified role
4. Delete invitation record
5. Invalidate any existing sessions for new access

### 4.3 Membership Management

#### 4.3.1 List Members

```
GET /v1/organizations/{organization_identifier}/members
Authorization: Bearer [session_jwt]
```

Returns all active memberships (no pending state in membership table).

#### 4.3.2 Update Member Role

```
PATCH /v1/organizations/{organization_identifier}/members/{user_id}
Authorization: Bearer [session_jwt]
{
  "role": "admin"
}
```

**Rules**:

- Only 'owner' can change roles
- Cannot remove last 'owner'
- Role changes trigger session invalidation

#### 4.3.3 Remove Member

```
DELETE /v1/organizations/{organization_identifier}/members/{user_id}
Authorization: Bearer [session_jwt]
```

**Rules**:

- 'owner' can remove anyone except last owner
- 'admin' can remove 'member' role only
- Members can remove themselves
- Removal cascades to revoke all sessions for that user-organization

### 4.4 Organization Deletion

```
DELETE /v1/organizations/{organization_identifier}
Authorization: Bearer [session_jwt]
```

**Rules**:

- Only 'owner' can delete organization
- Cannot delete if it's any user's `default_organization` (FK RESTRICT)
- Cascades to delete:
    - All memberships
    - All invitations
    - All sessions
    - All API keys
    - All service keys

---

## Section 5: Credential Management

### 5.1 Session Lifecycle

#### 5.1.1 Session Creation

Sessions are created during sign-in or organization switching:

```json5
// JWT Payload Structure
{
  "sub": "user_identifier",
  "organization": "organization_identifier",
  "sid": "session_identifier",
  "gen": 1,
  // generation number
  "role": "member",
  "iat": 1234567890,
  "exp": 1234571490
  // iat + 3600
}
```

#### 5.1.2 Session Refresh

Sessions are refreshed in two scenarios:

**Manual Refresh** (user-initiated):

```
POST /v1/sessions/refresh
Authorization: Bearer [old_jwt]
```

Returns new JWT with updated generation and fresh expiry.

**Silent Rotation** (validator-initiated):
When a validator detects a generation mismatch:

1. Validator has cached that session needs generation 2
2. User presents JWT with generation 1
3. Validator automatically calls `/v1/sessions/refresh` on user's behalf
4. Validator returns new JWT in `X-Refreshed-Token` header
5. Validator proceeds with the original API call using the new session context
6. Client library updates stored token for future requests

This ensures:

- Users get updated roles/permissions immediately
- No failed requests due to generation mismatches
- Transparent session rotation without user intervention

#### 5.1.3 Session Revocation

```
DELETE /v1/sessions/{session_id}
Authorization: Bearer [session_jwt]
```

Adds entry to `session_revocations` table.

#### 5.1.4 Organization Switching

```
POST /v1/sessions/switch
Authorization: Bearer [current_jwt]
{
  "organization_identifier": "target_org_id"
}
```

Creates new session for target organization, preserving user context.

### 5.2 API Key Management

#### 5.2.1 Create API Key

```
POST /v1/organizations/{organization_identifier}/api-keys
Authorization: Bearer [session_jwt]
{
  "role": "readonly"
}
```

**Response**:

```json5
{
  "key_id": "uuid",
  "secret": "organization_uuid_randomsecret",
  // Only shown once
  "role": "readonly",
  "created_at": "2025-01-01T00:00:00Z"
}
```

#### 5.2.2 Exchange for API Session

```
POST /v1/sessions/api
Authorization: Bearer org_uuid_randomsecret
```

Returns short-lived JWT (15 minutes) for better performance than bcrypt on every request.

#### 5.2.3 List API Keys

```
GET /v1/organizations/{organization_identifier}/api-keys
Authorization: Bearer [session_jwt]
```

Returns keys without secrets (never retrievable after creation).

#### 5.2.4 Revoke API Key

```
DELETE /v1/organizations/{organization_identifier}/api-keys/{key_id}
Authorization: Bearer [session_jwt]
```

### 5.3 Service Key Management

#### 5.3.1 Create Service Key

```
POST /v1/organizations/{organization_identifier}/service-keys
Authorization: Bearer [session_jwt]
{
  "role": "service",
  "resource_ids": ["resource1", "resource2"],
  "expires_in_seconds": 86400
}
```

**Response**:

```json5
{
  "key_id": "uuid",
  "secret": "service_uuid_randomsecret",
  // Only shown once
  "role": "service",
  "resource_ids": [
    "resource1",
    "resource2"
  ],
  "expires_at": "2025-01-02T00:00:00Z",
  "created_at": "2025-01-01T00:00:00Z"
}
```

#### 5.3.2 Exchange for Service Session

```
POST /v1/sessions/service
Authorization: Bearer svc_uuid_randomsecret
```

Returns short-lived JWT (15 minutes) with embedded resource constraints.

### 5.4 Token Validation

#### 5.4.1 Validator Library Algorithm

```python
def validate_token(token, validator_cache):
    if token.startswith("ey"):  # JWT
        claims = verify_es256_signature(token, validator_cache.public_key)
        
        # Check revocation from in-memory cache
        if claims['sid'] in validator_cache.revoked_sessions:
            return Error(401, "Session revoked")
        
        # Check generation from in-memory cache
        latest_gen = validator_cache.session_generations.get(claims['sid'])
        if latest_gen and claims['gen'] < latest_gen:
            # Silent rotation: get new token on user's behalf
            new_token = call_api("/v1/sessions/refresh", token)
            new_claims = decode_jwt(new_token)
            # Return both new token and claims for this request
            return Success(claims=new_claims, new_token=new_token)
        
        # Check expiry
        if claims['exp'] < time.now():
            return Error(401, "Token expired")
            
        return Success(claims=claims)
        
    elif token.startswith("org_"):  # API Key
        # Extract key_id from token
        # Bcrypt compare with stored hash
        # Return bound organization and role
        
    elif token.startswith("svc_"):  # Service Key
        # Extract key_id from token
        # Bcrypt compare with stored hash
        # Check expiry
        # Return organization, user, role, resources
```

#### 5.4.2 Validator Cache Management

The validator maintains an in-memory cache that is refreshed periodically:

```python
class ValidatorCache:
    def __init__(self):
        self.revoked_sessions = set()  # Set of revoked session IDs
        self.session_generations = {}  # Map of session_id -> latest_generation
        self.public_key = None         # Current ES256 public key
        self.config_version = 0        # Current configuration version
    
    def refresh_cache(self):
        """Called every revocation_poll_seconds (60 seconds)"""
        # Fetch all revoked sessions
        self.revoked_sessions = fetch_revoked_session_ids()
        
        # Fetch all sessions needing invalidation
        self.session_generations = fetch_session_latest_generations()
        
        # Check configuration version
        new_version = fetch_config_version()
        if new_version > self.config_version:
            self.public_key = fetch_current_public_key()
            self.config_version = new_version
```

#### 5.4.3 Client Library Session Rotation

When the validator returns a new token, client libraries handle it transparently:

```python
def make_api_call(endpoint, token):
    response = http_client.get(
        endpoint,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Check for rotated session in response header
    if "X-Refreshed-Token" in response.headers:
        new_token = response.headers["X-Refreshed-Token"]
        # Store new token for future requests
        token_store.update(new_token)
        # Current request already used new token context
    
    return response
```

#### 5.4.4 Polling Intervals

Validators use two different polling intervals:

- **Revocation/Invalidation Poll**: Every <configurable> seconds (high priority)
    - Fetches revoked session IDs
    - Fetches session generation updates
- **Configuration Poll**: Every <configurable> seconds (low priority)
    - Checks for configuration version changes
    - Updates JWKS if needed

### 5.5 Key Rotation

#### 5.5.1 Rotation Process

```
POST /v1/admin/keys/rotate
Authorization: Bearer [admin_session]
```

1. Generate new ES256 key pair
2. Update configuration table with new keys
3. Increment `config_version`
4. Keep old public key for grace period
5. Trigger session invalidation for all active sessions

#### 5.5.2 Validator Response

- Polls configuration every 300 seconds
- On version change, fetches new JWKS
- Maintains old and new keys during transition
- Old sessions verified with old key until refresh

---

## Section 6: Security Considerations

### 6.1 Password/Secret Management

#### 6.1.1 Bcrypt Configuration

- Cost factor: 12 (tunable based on hardware)
- All passwords/secrets bcrypt hashed
- Unique salt per credential
- Timing-safe comparison functions

#### 6.1.2 Token Generation

- Cryptographically secure random generation
- Minimum 256 bits of entropy
- Base64URL encoding for URL-safe transmission

### 6.2 Rate Limiting

#### 6.2.1 Authentication Endpoints

- `/v1/authentication/*`: 5 attempts per email per minute
- `/v1/sessions/api`: 10 requests per API key per minute
- `/v1/authentication/device/poll`: 1 request per 5 seconds per device

#### 6.2.2 Administrative Endpoints

- `/v1/organizations/*/invitations`: 20 per hour per organization
- `/v1/admin/keys/rotate`: 1 per hour globally

### 6.3 Audit Logging

Log these events with timestamp, actor, IP:

- User creation/deletion
- Sign-in attempts (success/failure)
- Identity linking/unlinking
- Organization creation/deletion
- Membership changes
- Invitation creation/acceptance/approval
- API/Service key creation/revocation
- Session revocation
- Key rotation

### 6.4 Data Privacy

#### 6.4.1 PII Handling

- Email addresses normalized and indexed for uniqueness
- No password storage (only OAuth or magic links)
- Provider tokens never stored (only exchange immediately)
- IP addresses logged for security, purged after 90 days

#### 6.4.2 Token Privacy

- Secrets shown once at creation
- Never logged in plaintext
- Not retrievable via API
- Revoked tokens purged after expiry

### 6.5 CORS & CSP

#### 6.5.1 CORS Policy

```
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PATCH, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Max-Age: 86400
```

#### 6.5.2 Content Security Policy

```
Content-Security-Policy: default-src 'self'; 
  script-src 'self'; 
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self';
  frame-ancestors 'none';
```

---

## Section 7: API Specification

### 7.1 Base Configuration

- Base URL: `https://authentication.example.com/v1`
- Content-Type: `application/json`
- Authentication: Bearer token (JWT or API key)
- Error format: RFC 9457 (Problem Details)

### 7.2 Standard Headers

#### Request Headers

```
Authorization: Bearer [token]
Content-Type: application/json
X-Request-ID: [uuid]  // Optional, for tracing
```

#### Response Headers

```
X-Request-ID: [uuid]  // Echoed or generated
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1234567890
X-Refreshed-Token: [new_jwt]  // Present when session was silently rotated
```

**Session Rotation Header**:
When a session's generation is outdated, validators perform silent rotation and return the new token in
`X-Refreshed-Token`. Client libraries should:

1. Extract and store the new token
2. Use it for all future requests
3. Note that the current request was already processed with the new token's context (updated roles/permissions)

### 7.3 Error Response Format

```json
{
  "type": "https://authentication.example.com/errors/unauthorized",
  "title": "Authentication required",
  "status": 401,
  "detail": "The provided token has expired",
  "instance": "/v1/organizations/123/members"
}
```

### 7.4 Core Endpoints

#### 7.4.1 Authentication & Sessions

| Method | Path                                   | Authentication | Description                    |
|--------|----------------------------------------|----------------|--------------------------------|
| POST   | `/v1/authentication/device`            | None           | Initiate device flow           |
| POST   | `/v1/authentication/device/poll`       | None           | Poll for device authentication |
| POST   | `/v1/authentication/magic-link`        | None           | Request magic link             |
| POST   | `/v1/authentication/magic-link/redeem` | None           | Redeem magic link              |
| POST   | `/v1/oauth/google/authorize`           | None           | Start Google OAuth             |
| GET    | `/v1/oauth/google/callback`            | None           | Google OAuth callback          |
| POST   | `/v1/oauth/github/authorize`           | None           | Start GitHub OAuth             |
| GET    | `/v1/oauth/github/callback`            | None           | GitHub OAuth callback          |
| POST   | `/v1/sessions/refresh`                 | JWT            | Refresh session token          |
| POST   | `/v1/sessions/switch`                  | JWT            | Switch organization            |
| POST   | `/v1/sessions/api`                     | API Key        | Get API session                |
| POST   | `/v1/sessions/service`                 | Service Key    | Get service session            |
| DELETE | `/v1/sessions/{identifier}`            | JWT            | Revoke session                 |

#### 7.4.2 Account Management

| Method | Path                                       | Authentication | Description      |
|--------|--------------------------------------------|----------------|------------------|
| GET    | `/v1/account`                              | JWT            | Get current user |
| PATCH  | `/v1/account`                              | JWT            | Update user      |
| DELETE | `/v1/account`                              | JWT            | Delete user      |
| POST   | `/v1/account/link/google`                  | JWT            | Link Google      |
| POST   | `/v1/account/link/github`                  | JWT            | Link GitHub      |
| POST   | `/v1/account/link/magic`                   | JWT            | Link email       |
| DELETE | `/v1/account/link/{provider}/{identifier}` | JWT            | Unlink identity  |

#### 7.4.3 Organization Management

| Method | Path                             | Authentication | Description               |
|--------|----------------------------------|----------------|---------------------------|
| GET    | `/v1/organizations`              | JWT            | List user's organizations |
| POST   | `/v1/organizations`              | JWT            | Create organization       |
| GET    | `/v1/organizations/{identifier}` | JWT            | Get organization details  |
| PATCH  | `/v1/organizations/{identifier}` | JWT/Owner      | Update organization       |
| DELETE | `/v1/organizations/{identifier}` | JWT/Owner      | Delete organization       |

#### 7.4.4 Membership Management

| Method | Path                                            | Authentication | Description   |
|--------|-------------------------------------------------|----------------|---------------|
| GET    | `/v1/organizations/{identifier}/members`        | JWT            | List members  |
| PATCH  | `/v1/organizations/{identifier}/members/{user}` | JWT/Admin      | Update role   |
| DELETE | `/v1/organizations/{identifier}/members/{user}` | JWT/Admin      | Remove member |

#### 7.4.5 Invitation Management

| Method | Path                                                       | Authentication | Description        |
|--------|------------------------------------------------------------|----------------|--------------------|
| GET    | `/v1/organizations/{identifier}/invitations`               | JWT/Admin      | List invitations   |
| POST   | `/v1/organizations/{identifier}/invitations`               | JWT/Admin      | Create invitation  |
| POST   | `/v1/invitations/accept`                                   | None           | Accept invitation  |
| POST   | `/v1/organizations/{identifier}/invitations/{inv}/approve` | JWT/Admin      | Approve acceptance |
| DELETE | `/v1/organizations/{identifier}/invitations/{inv}`         | JWT/Admin      | Cancel invitation  |

#### 7.4.6 Credential Management

| Method | Path                                                | Authentication | Description        |
|--------|-----------------------------------------------------|----------------|--------------------|
| GET    | `/v1/organizations/{identifier}/api-keys`           | JWT/Admin      | List API keys      |
| POST   | `/v1/organizations/{identifier}/api-keys`           | JWT/Admin      | Create API key     |
| DELETE | `/v1/organizations/{identifier}/api-keys/{key}`     | JWT/Admin      | Revoke API key     |
| GET    | `/v1/organizations/{identifier}/service-keys`       | JWT/Admin      | List service keys  |
| POST   | `/v1/organizations/{identifier}/service-keys`       | JWT/Admin      | Create service key |
| DELETE | `/v1/organizations/{identifier}/service-keys/{key}` | JWT/Admin      | Revoke service key |

#### 7.4.7 System Endpoints

| Method | Path                        | Authentication | Description         |
|--------|-----------------------------|----------------|---------------------|
| GET    | `/v1/.well-known/jwks.json` | None           | Public key set      |
| GET    | `/v1/health`                | None           | Health check        |
| GET    | `/v1/metrics`               | Internal       | Prometheus metrics  |
| POST   | `/v1/admin/keys/rotate`     | JWT/System     | Rotate signing keys |

### 7.5 Pagination

List endpoints support pagination:

```
GET /v1/organizations/{identifier}/members?limit=20&cursor=eyJpZCI6MTIzfQ
```

Response:

```json5
{
  "data": [],
  // arbitrary data
  "cursor": {
    "next": "eyJpZCI6MTQzfQ",
    "prev": "eyJpZCI6MTAzfQ"
  }
}
```

---

## Section 8: Operational Considerations

### 8.1 Database Maintenance

#### 8.1.1 Cleanup Jobs (Daily)

```sql
-- Remove expired sessions
DELETE
FROM sessions
WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 DAY);

-- Remove expired invitations  
DELETE
FROM invitations
WHERE expires_at < NOW();

-- Remove old flow records
DELETE
FROM device_code_flows
WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY);
DELETE
FROM google_oauth_flows
WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);
DELETE
FROM github_oauth_flows
WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);
DELETE
FROM magic_link_flows
WHERE created_at < DATE_SUB(NOW(), INTERVAL 2 HOURS);

-- Remove orphaned revocations
DELETE
sr FROM session_revocations sr 
LEFT JOIN sessions s ON sr.session_identifier = s.identifier 
WHERE s.identifier IS NULL;
```

#### 8.1.2 Index Maintenance

Monitor and rebuild fragmented indexes monthly:

- Primary keys (UUIDs can cause fragmentation)
- Email uniqueness indexes
- Membership lookup indexes

### 8.2 Monitoring & Alerting

#### 8.2.1 Key Metrics

- **Authentication Rate**: Successful/failed sign-ins per minute
- **Session Creation Rate**: New sessions per minute
- **Silent Rotation Rate**: Sessions auto-refreshed per minute
- **Token Validation Latency**: P50/P95/P99
- **Cache Hit Rate**: Percentage of validations using cached data
- **Database Connection Pool**: Active/idle/waiting
- **API Endpoint Latency**: Per endpoint P95
- **Error Rates**: 4xx/5xx per endpoint

#### 8.2.2 Critical Alerts

- Failed key rotation
- Database connection exhaustion
- Spike in failed authentications (potential attack)
- Expired SSL certificates
- Configuration version mismatch across instances

### 8.3 Backup & Recovery

#### 8.3.1 Backup Strategy

- **Full Backup**: Daily at 02:00 UTC
- **Incremental**: Every 6 hours
- **Transaction Logs**: Continuous to S3
- **Retention**: 30 days full, 90 days transaction logs

#### 8.3.2 Recovery Procedures

- **RPO**: 5 minutes (transaction log shipping)
- **RTO**: 30 minutes (automated failover)
- Test restore procedure monthly
- Maintain runbook for manual recovery

### 8.4 Performance Optimization

#### 8.4.1 Caching Strategy

- **JWKS**: Cache for 1 hour in CDN
- **Revocation List**: In-memory set refreshed every <configurable time> seconds
    - Critical for performance (avoiding DB lookups on every request)
    - Maximum staleness: <configurable time> seconds
- **Session Generations**: In-memory map refreshed every <configurable time> seconds
    - Maps session_identifier to latest generation
    - Enables silent token rotation
- **Session Data**: Optional Redis cache for hot sessions
- **Configuration**: In-memory with 5-minute refresh

**Cache Synchronization**:

- All validator instances poll the same tables
- <configurable time>-second refresh ensures consistency within 1 minute
- Silent rotation prevents request failures during the sync window
- New validators must populate cache before accepting traffic

#### 8.4.2 Query Optimization

Critical query patterns to optimize:

```sql
-- Session validation (most frequent)
SELECT *
FROM sessions
WHERE identifier = ?
  AND expires_at > NOW();

-- Membership check
SELECT role
FROM memberships
WHERE user_identifier = ?
  AND organization_identifier = ?;

-- Identity lookup
SELECT user_identifier
FROM [provider] _identities
WHERE provider_identifier = ?;
```

### 8.5 Scaling Considerations

#### 8.5.1 Horizontal Scaling

- Service instances: Stateless, scale based on CPU/latency
- Database: Read replicas for validation queries
- Cache layer: Redis Cluster for session cache

#### 8.5.2 Capacity Planning

Per 1000 active users:

- ~5000 sessions/day
- ~50,000 validations/day
- ~10GB database growth/year
- ~100 req/sec peak validation load

---

## Section 9: Migration & Deployment

### 9.1 Database Migration Strategy

#### 9.1.1 Goose Migration Files

```bash
migrations/
├── 001_initial_schema.sql       # Core tables
├── 002_add_indexes.sql          # Performance indexes
├── 003_add_configuration.sql    # Config table with defaults
└── 004_future_changes.sql       # Template for changes
```

#### 9.1.2 Zero-Downtime Migrations

1. Add new columns as nullable
2. Deploy code that writes both old and new
3. Backfill existing data
4. Deploy code that reads new column
5. Drop old column in next release

### 9.2 Deployment Process

#### 9.2.1 Blue-Green Deployment

1. Deploy to green environment
2. Run smoke tests
3. Switch load balancer
4. Monitor error rates
5. Keep blue environment for quick rollback

#### 9.2.2 Feature Flags

Control rollout of new features:

- OAuth provider enablement
- New role types
- API versioning
- Rate limit adjustments

### 9.4 Validator Library Deployment

#### 9.4.1 Embedded Validator Model

The validator is not a separate service but a library embedded in each backend service:

```
┌──────────────────┐     ┌──────────────────┐
│  API Service     │     │  Worker Service  │
│  ┌────────────┐  │     │  ┌────────────┐  │
│  │ Validator  │  │     │  │ Validator  │  │
│  │  Library   │  │     │  │  Library   │  │
│  │ (In-Memory │  │     │  │ (In-Memory │  │
│  │   Cache)   │  │     │  │   Cache)   │  │
│  └──────┬─────┘  │     │  └──────┬─────┘  │
└─────────┼────────┘     └─────────┼────────┘
          │                        │
          └────────┬───────────────┘
                   │
                   ▼ Polls every 60s
         ┌─────────────────┐
         │   Authentication Service  │
         │   Database      │
         └─────────────────┘
```

#### 9.4.2 Validator Initialization

```python
# Each service initializes its own validator instance
validator = AuthValidator(
    auth_service_url="https://authentication.internal",
    poll_interval=60,  # seconds
    config_poll_interval=300,  # seconds
    cache_implementation=InMemoryCache()  # or RedisCache() for shared cache
)

# Start background polling
validator.start_polling()

# Use in request handler
def handle_request(request):
    result = validator.validate(request.headers["Authorization"])
    if result.error:
        return 401
    if result.new_token:
        # Silent rotation occurred
        response.headers["X-Refreshed-Token"] = result.new_token
    # Process request with result.claims
```

#### 9.4.3 Cache Warming

New validator instances must warm their cache before accepting traffic:

1. Fetch all revoked sessions
2. Fetch all session generations
3. Fetch current JWKS
4. Mark instance as healthy only after cache populated

#### 9.4.4 Graceful Shutdown

On shutdown, validators should:

1. Stop accepting new requests
2. Complete in-flight validations
3. Stop polling threads
4. Clear sensitive data from memory

---

## Section 10: Appendices

### 10.1 Role Definitions

Standard roles (stored lowercase):

- **owner**: Full control, can delete organization
- **admin**: Manage members and settings
- **member**: Basic access
- **readonly**: View-only access
- **service**: System-to-system access

### 10.2 Token Formats

#### 10.2.1 Session JWT

```
Header:
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "key-id-from-jwks"
}

Payload:
{
  "sub": "user_identifier",
  "organization": "organization_identifier", 
  "sid": "session_identifier",
  "gen": 1,
  "role": "member",
  "iat": 1234567890,
  "exp": 1234571490
}
```

#### 10.2.2 API Key Format

```
org_[key_identifier]_[32_random_bytes_base64url]
```

#### 10.2.3 Service Key Format

```
svc_[key_identifier]_[32_random_bytes_base64url]
```

### 10.3 Database Connection String

```
mysql://auth_service:password@mysql.internal:3306/auth_db?parseTime=true&loc=UTC
```

Options:

- `parseTime=true`: Parse DATETIME to time.Time
- `loc=UTC`: Store all times in UTC
- Connection pool: 25 connections
- Max idle: 5 connections
- Connection lifetime: 5 minutes

### 10.4 Compliance Considerations

#### 10.4.1 GDPR Compliance

- Right to erasure: User deletion cascades all data
- Data portability: Export user's identities and memberships
- Data minimization: Only store necessary authentication data
- Consent: Explicit acceptance of invitations

#### 10.4.2 SOC2 Requirements

- Encryption in transit: TLS 1.2+ required
- Encryption at rest: Database encryption
- Access logging: All authentication events
- Change management: Migration version control

---

## Revision History

| Version | Date       | Author | Changes                                         |
|---------|------------|--------|-------------------------------------------------|
| 4.0     | 2025-08-05 | -      | Initial specification based on finalized schema |

---

*End of Specification*