# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building
```bash
go build ./...
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...

# Run a specific test
go test -run TestSession ./pkg/session
```

### Dependencies
```bash
# Download dependencies
go mod download

# Tidy dependencies
go mod tidy

# Update dependencies
go get -u ./...
```

### API Documentation
The project uses Swagger for API documentation. OpenAPI specs are located in:
- `internal/api/v1/docs/authAPI_swagger.json`
- `internal/api/v1/docs/authAPI_swagger.yaml`

## Architecture Overview

This is a Go authentication library designed for use within Loophole Labs projects. The architecture follows a modular design with clear separation of concerns:

### Core Components

1. **Main Entry Point** (`auth.go`)
   - Provides the `Auth` struct that orchestrates the entire authentication system
   - Manages lifecycle (Start/Stop) of the authentication service
   - Integrates the Controller and API components

2. **Storage Interface** (`pkg/storage/`)
   - Defines abstract interfaces for data persistence
   - Implementations must provide: User, Registration, SecretKey, Session, APIKey, ServiceKey, ServiceSession, Flow, and Health storage
   - Uses `ErrNotFound` and `ErrAlreadyExists` for consistent error handling

3. **API Layer** (`internal/api/`)
   - RESTful API built with Fiber framework
   - Versioned API (currently v1) mounted at `/v1`
   - Supports multiple authentication providers:
     - Device Code Flow
     - GitHub OAuth
     - Google OAuth  
     - Magic Link (email-based)
   - Each provider has its own configuration and can be independently enabled/disabled

4. **Authentication Flows** (`pkg/flow/`)
   - Each authentication method (device, github, google, magic) has its own flow implementation
   - Flows handle the authentication state machine and validation logic

5. **Session Management** (`pkg/session/`)
   - Handles user sessions with expiration tracking
   - Sessions track: device status, provider, creator, and organization

6. **Controller** (`internal/controller/`)
   - Manages authentication business logic
   - Coordinates between storage, sessions, and authentication flows

7. **Configuration** (`pkg/config/`)
   - Structured configuration with validation
   - Supports command-line flags via pflag
   - Separate API configuration with provider-specific settings

### Key Design Patterns

- **Interface-based Storage**: The storage layer is completely abstracted, allowing different backend implementations
- **Provider Pattern**: Authentication providers (GitHub, Google, etc.) follow a consistent interface
- **Options Pattern**: Configuration uses Options structs for clean initialization
- **Context-based Lifecycle**: Uses Go contexts for graceful shutdown

### Security Features

- AES encryption utilities (`internal/aes/`)
- Session domain and TLS configuration
- API key and service key support for machine-to-machine auth
- PKCE support for OAuth flows (via grokify/go-pkce)

### External Dependencies

- **Fiber v2**: High-performance web framework
- **Loophole Labs Logging**: Structured logging with OpenTelemetry support
- **go-openapi**: For API client generation and validation
- **Postmark**: Email service for magic links
- **Various OAuth2 libraries**: For GitHub and Google authentication

## Current Authentication Controller Implementation

The authentication controller (`internal/controller/controller.go`) is the heart of the authentication system. Here's a detailed analysis of its current implementation:

### Controller Architecture

#### In-Memory Caching with Event Subscriptions
The controller maintains in-memory maps for performance optimization:
- `sessions`: Map of session IDs (existence only)
- `serviceSessions`: Map of service session objects
- `apikeys`: Map of API key objects

These maps are synchronized with the storage backend through event subscriptions:
- `SubscribeToSecretKey`: Updates encryption keys
- `SubscribeToRegistration`: Updates registration state
- `SubscribeToSessions`: Updates session existence
- `SubscribeToServiceSessions`: Updates service session cache
- `SubscribeToAPIKeys`: Updates API key cache

#### Three Authentication Types

1. **Sessions** (Browser-based)
   - Created via `CreateSession()` with user ID, provider, and organization
   - Stored as AES-encrypted JSON in HTTP-only cookies
   - 7-day expiry with automatic refresh when close to expiry (within 24 hours)
   - Validated by decrypting cookie and checking in-memory map (falls back to storage)

2. **Service Sessions** (Service Key-based)
   - Created via `CreateServiceSession()` using service keys
   - Returns session ID and secret for Bearer token authentication
   - Inherits permissions and resources from parent service key
   - Validated using bcrypt hash comparison

3. **API Keys** (Direct key-based)
   - Pre-created keys stored in the system
   - Used directly in Bearer token authentication
   - Validated using bcrypt hash comparison

#### Authentication Flow

The `Validate()` method checks in order:
1. Session cookie (if present)
2. Bearer token in Authorization header:
   - API Key format: `Bearer ak_<id>.<secret>`
   - Service Session format: `Bearer ss_<id>.<secret>`

Each successful validation sets context locals:
- `KindContext`: Type of authentication (Session/ServiceSession/APIKey)
- `UserContext`: User identifier
- `OrganizationContext`: Organization scope
- Session/ServiceSession/APIKey object in respective context keys

#### Current Issues with fiber.Ctx Dependency

All controller methods accept `*fiber.Ctx` instead of standard `context.Context`, creating tight coupling:
- `CreateSession(ctx *fiber.Ctx, ...)`
- `CreateServiceSession(ctx *fiber.Ctx, ...)`
- `Validate(ctx *fiber.Ctx)`
- `ManualValidate(ctx *fiber.Ctx)`
- `LogoutSession(ctx *fiber.Ctx)`
- `LogoutServiceSession(ctx *fiber.Ctx)`

This design:
- Makes the controller non-portable (tied to Fiber framework)
- Complicates testing (requires Fiber context setup)
- Violates separation of concerns (business logic mixed with HTTP handling)

#### Session Management Details

**Creation**:
- Checks user existence (creates if registration enabled)
- Validates organization membership
- Generates UUID-based session ID
- Encrypts session data with AES using a rotating secret key
- Stores in both storage backend and in-memory map

**Validation**:
- Decrypts cookie using current or old secret key
- Checks expiry and existence in memory (with storage fallback)
- Auto-refreshes if using old key or close to expiry
- Updates cookie with new encryption if refreshed

**Secret Key Rotation**:
- Maintains current and old secret keys
- Allows graceful migration during key rotation
- Old key used as fallback for decryption only

### Proposed JWT-Based Architecture

The current architecture could be improved by:
1. Replacing AES-encrypted cookies with JWT tokens
2. Using standard `context.Context` instead of `*fiber.Ctx`
3. Implementing a revocation list with background polling
4. Separating HTTP concerns from authentication logic
5. Making the controller framework-agnostic

## Storage Interface Documentation

The storage interface (`pkg/storage/`) is the abstraction layer for all data persistence in the authentication system. It's designed to be implemented by the application using this auth library.

### Storage Interface Composition

The main `Storage` interface is composed of 9 sub-interfaces:
```go
type Storage interface {
    User
    Registration
    SecretKey
    Session
    APIKey
    ServiceKey
    ServiceSession
    Flow
    Health
    
    Shutdown() error
}
```

### Sub-Interface Details

#### 1. **User Interface**
Manages user data and organization membership:
- `UserExists(ctx, identifier)`: Check if user exists
- `UserOrganizationExists(ctx, identifier, organization)`: Verify organization membership
- `UserDefaultOrganization(ctx, identifier)`: Get user's default organization
- `NewUser(ctx, claims)`: Create new user with claims

**Usage in Controller**:
- Called during session creation to validate users
- Auto-creates users if registration is enabled
- Validates organization membership for scoped sessions

#### 2. **Registration Interface**
Controls whether new users can be auto-created:
- `SetRegistration(ctx, enabled)`: Enable/disable registration
- `GetRegistration(ctx)`: Check registration status
- `SubscribeToRegistration(ctx)`: Real-time registration changes

**Event Pattern**: Publishes `RegistrationEvent{Enabled: bool}`

#### 3. **SecretKey Interface**
Manages AES encryption keys for sessions:
- `SetSecretKey(ctx, secretKey)`: Store 32-byte key
- `GetSecretKey(ctx)`: Retrieve current key
- `SubscribeToSecretKey(ctx)`: Key rotation events

**Event Pattern**: Publishes `SecretKeyEvent` (32-byte array)
**Key Rotation**: Controller maintains current and old keys for graceful migration

#### 4. **Session Interface**
Handles browser-based authentication sessions:
- `SetSession(ctx, session)`: Create new session
- `GetSession(ctx, id)`: Retrieve session by ID
- `ListSessions(ctx)`: Get all sessions (used at startup)
- `DeleteSession(ctx, id)`: Remove session
- `UpdateSessionExpiry(ctx, id, expiry)`: Refresh expiration
- `SubscribeToSessions(ctx)`: Session CRUD events

**Event Pattern**: `SessionEvent{Identifier, Deleted, Session}`
**In-Memory Caching**: Controller caches session IDs for fast validation

#### 5. **APIKey Interface**
Manages API keys for machine authentication:
- `GetAPIKey(ctx, identifier)`: Retrieve API key
- `ListAPIKeys(ctx)`: Get all keys (cached at startup)
- `SubscribeToAPIKeys(ctx)`: Key CRUD events

**Event Pattern**: `APIKeyEvent{Identifier, Deleted, APIKey}`
**Note**: No create/update methods - API keys are pre-created externally

#### 6. **ServiceKey Interface**
Handles service keys (parent of service sessions):
- `GetServiceKey(ctx, identifier)`: Retrieve service key
- `IncrementServiceKeyNumUsed(ctx, identifier, increment)`: Track usage

**No Events**: Service keys don't have subscription support

#### 7. **ServiceSession Interface**
Manages sessions created from service keys:
- `SetServiceSession(ctx, identifier, salt, hash, serviceKeyID)`: Create session
- `GetServiceSession(ctx, identifier)`: Retrieve session
- `ListServiceSessions(ctx)`: Get all (cached at startup)
- `DeleteServiceSession(ctx, identifier)`: Remove session
- `SubscribeToServiceSessions(ctx)`: Session CRUD events

**Event Pattern**: `ServiceSessionEvent{Identifier, Deleted, ServiceSession}`

#### 8. **Flow Interface**
Composed of 4 authentication flow sub-interfaces:

**Device Flow**:
- `SetDeviceFlow`: Store device code flow
- `GetDeviceFlow`: Retrieve by device code
- `UpdateDeviceFlow`: Add session after approval
- `GetDeviceFlowUserCode`: Find by user code
- `GetDeviceFlowIdentifier`: Find by flow ID
- `DeleteDeviceFlow`: Remove flow
- `GCDeviceFlow`: Garbage collect expired flows

**GitHub/Google OAuth Flows**:
- `Set[Github|Google]Flow`: Store OAuth state
- `Get[Github|Google]Flow`: Retrieve by state
- `Delete[Github|Google]Flow`: Clean up after use
- `GC[Github|Google]Flow`: Garbage collect expired

**Magic Link Flow**:
- `SetMagicFlow`: Store email verification
- `GetMagicFlow`: Retrieve by email
- `DeleteMagicFlow`: Clean up after use
- `GCMagicFlow`: Garbage collect expired

#### 9. **Health Interface**
Monitors storage subscription health:
- `Errors()`: Returns `HealthErrors` struct with subscription errors

### Storage Usage Patterns

#### Event Subscription Pattern
All event channels follow these rules:
1. **Reliability**: Storage must handle network errors internally
2. **Lifecycle**: Channels close only when context is cancelled
3. **Startup**: Controller subscribes before loading initial data
4. **Consistency**: Events ensure in-memory cache stays synchronized

#### Error Handling
Two standard errors are defined:
- `ErrNotFound`: Resource doesn't exist
- `ErrAlreadyExists`: Resource already exists

#### Context Usage
All methods accept `context.Context` for:
- Cancellation support
- Timeout handling
- Request-scoped values

### Current Implementation Gaps

1. **No Tests**: Storage interfaces are completely untested
2. **No Reference Implementation**: No in-memory or example implementation
3. **Limited Service Key Operations**: Can't create/list service keys
4. **No Batch Operations**: Each operation is individual
5. **No Transaction Support**: No way to ensure atomicity across operations

### Critical Storage Operations

The controller relies heavily on storage for:
1. **Startup**: Loading all sessions, API keys, and settings
2. **Validation**: Fallback when in-memory cache misses
3. **Event Streaming**: Keeping distributed instances in sync
4. **Flow State**: Managing OAuth and device flows
5. **Garbage Collection**: Cleaning up expired flows

Any JWT-based rewrite must maintain these storage contracts or provide migration paths.