//SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jellydator/ttlcache/v3"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/db/pgxtypes"
	"github.com/loopholelabs/auth/internal/mailer"
	"github.com/loopholelabs/auth/pkg/credential"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/flow/device"
	"github.com/loopholelabs/auth/pkg/manager/flow/github"
	"github.com/loopholelabs/auth/pkg/manager/flow/google"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
	"github.com/loopholelabs/auth/pkg/manager/role"
)

const (
	Timeout        = time.Second * 30
	GCInterval     = time.Minute
	HealthInterval = time.Second * 30
	Jitter         = time.Second * 5
	ForcedRefresh  = time.Hour
)

var (
	ErrCreatingManager    = errors.New("error creating manager")
	ErrDBIsRequired       = errors.New("db is required")
	ErrCreatingSession    = errors.New("error creating session")
	ErrRefreshingSession  = errors.New("error refreshing session")
	ErrRevokingSession    = errors.New("error revoking session")
	ErrInvalidProvider    = errors.New("invalid provider")
	ErrInvalidFlowData    = errors.New("invalid flow data")
	ErrSessionIsExpired   = errors.New("session is expired")
	ErrInvalidSessionRole = errors.New("invalid session role")
	ErrValidatingSession  = errors.New("error validating session")
	ErrRevokedSession     = errors.New("revoked session")
)

type InvalidatedSession struct {
	Identifier string `json:"identifier"`
	Generation uint32 `json:"generation"`
}

type GithubOptions struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
}

type GoogleOptions struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
}

type MagicOptions struct {
	Enabled bool
}

type DeviceOptions struct {
	Enabled bool
}

type MailerOptions struct {
	Enabled               bool
	Mailer                mailer.Mailer
	SMTPHost              string
	SMTPPort              int
	SMTPUsername          string
	SMTPPassword          string
	FromEmail             string
	FromName              string
	AppName               string
	MagicLinkTemplatePath string
}

type APIOptions struct {
	TLS      bool
	Endpoint string
}

type Options struct {
	Github        GithubOptions
	Google        GoogleOptions
	Magic         MagicOptions
	Device        DeviceOptions
	Mailer        MailerOptions
	Configuration configuration.Options
	API           APIOptions
}

type Manager struct {
	logger types.Logger
	db     *db.DB

	configuration *configuration.Configuration

	github *github.Github
	google *google.Google
	magic  *magic.Magic
	device *device.Device

	mailer mailer.Mailer

	sessionRevocationCache   *ttlcache.Cache[string, struct{}]
	sessionInvalidationCache *ttlcache.Cache[string, uint32]

	sessionRevocationHealthy   bool
	sessionInvalidationHealthy bool

	healthy bool
	mu      sync.RWMutex

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func New(options Options, db *db.DB, logger types.Logger) (*Manager, error) {
	logger = logger.SubLogger("MANAGER")
	if db == nil {
		return nil, errors.Join(ErrCreatingManager, ErrDBIsRequired)
	}

	c, err := configuration.New(options.Configuration, db, logger)
	if err != nil {
		return nil, errors.Join(ErrCreatingManager, err)
	}

	var endpoint url.URL
	endpoint.Scheme = "http"
	if options.API.TLS {
		endpoint.Scheme = "https"
	}
	endpoint.Host = options.API.Endpoint
	endpoint.Path = "/v1/flows"

	var gh *github.Github
	if options.Github.Enabled {
		gh, err = github.New(github.Options{
			RedirectURL:  endpoint.JoinPath("/github/callback").String(),
			ClientID:     options.Github.ClientID,
			ClientSecret: options.Github.ClientSecret,
		}, db, logger)
		if err != nil {
			return nil, errors.Join(ErrCreatingManager, err)
		}
	}

	var gg *google.Google
	if options.Google.Enabled {
		gg, err = google.New(google.Options{
			RedirectURL:  endpoint.JoinPath("/google/callback").String(),
			ClientID:     options.Google.ClientID,
			ClientSecret: options.Google.ClientSecret,
		}, db, logger)
		if err != nil {
			return nil, errors.Join(ErrCreatingManager, err)
		}
	}

	var mg *magic.Magic
	if options.Magic.Enabled {
		mg, err = magic.New(db, logger)
		if err != nil {
			return nil, errors.Join(ErrCreatingManager, err)
		}
	}

	var dv *device.Device
	if options.Device.Enabled {
		dv, err = device.New(db, logger)
		if err != nil {
			return nil, errors.Join(ErrCreatingManager, err)
		}
	}

	var ml mailer.Mailer
	if options.Mailer.Enabled {
		if options.Mailer.Mailer != nil {
			ml = options.Mailer.Mailer
		} else {
			ml, err = mailer.New(mailer.Config{
				SMTPHost:              options.Mailer.SMTPHost,
				SMTPPort:              options.Mailer.SMTPPort,
				SMTPUsername:          options.Mailer.SMTPUsername,
				SMTPPassword:          options.Mailer.SMTPPassword,
				FromEmail:             options.Mailer.FromEmail,
				FromName:              options.Mailer.FromName,
				AppName:               options.Mailer.AppName,
				MagicLinkTemplatePath: options.Mailer.MagicLinkTemplatePath,
			})
			if err != nil {
				return nil, errors.Join(ErrCreatingManager, err)
			}
		}
	}

	sessionRevocationCache := ttlcache.New[string, struct{}](ttlcache.WithTTL[string, struct{}](c.SessionExpiry()))
	sessionInvalidationCache := ttlcache.New[string, uint32](ttlcache.WithTTL[string, uint32](c.SessionExpiry()))

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		logger:                   logger,
		db:                       db,
		configuration:            c,
		github:                   gh,
		google:                   gg,
		magic:                    mg,
		device:                   dv,
		mailer:                   ml,
		sessionRevocationCache:   sessionRevocationCache,
		sessionInvalidationCache: sessionInvalidationCache,
		ctx:                      ctx,
		cancel:                   cancel,
	}

	m.sessionRevocationsRefresh()
	m.sessionInvalidationsRefresh()

	m.healthCheck()

	m.wg.Add(1)
	go m.doSessionGC()

	m.wg.Add(1)
	go m.doSessionRevocationGC()

	m.wg.Add(1)
	go m.doRefresh()

	m.wg.Add(1)
	go m.doHealthCheck()

	return m, nil
}

func (m *Manager) Github() *github.Github {
	return m.github
}

func (m *Manager) Google() *google.Google {
	return m.google
}

func (m *Manager) Magic() *magic.Magic {
	return m.magic
}

func (m *Manager) Device() *device.Device {
	return m.device
}

func (m *Manager) Mailer() mailer.Mailer {
	return m.mailer
}

func (m *Manager) Configuration() *configuration.Configuration {
	return m.configuration
}

func (m *Manager) CreateSession(ctx context.Context, data flow.Data, provider flow.Provider) (credential.Session, error) {
	if data.ProviderIdentifier == "" {
		return credential.Session{}, errors.Join(ErrCreatingSession, ErrInvalidFlowData)
	}
	if len(data.VerifiedEmails) < 1 {
		return credential.Session{}, errors.Join(ErrCreatingSession, ErrInvalidFlowData)
	}
	verifiedEmails, err := json.Marshal(data.VerifiedEmails)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	params := generated.GetIdentityByProviderAndProviderIdentifierParams{
		ProviderIdentifier: data.ProviderIdentifier,
	}
	switch provider {
	case flow.GithubProvider:
		params.Provider = "GITHUB"
	case flow.GoogleProvider:
		params.Provider = "GOOGLE"
	case flow.MagicProvider:
		params.Provider = "MAGIC"
	default:
		return credential.Session{}, errors.Join(ErrCreatingSession, ErrInvalidProvider)
	}

	tx, err := m.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			m.logger.Error().Err(err).Str("provider", provider.String()).Str("provider_identifier", data.ProviderIdentifier).Str("primary_email", data.PrimaryEmail).Msg("failed to rollback transaction")
		}
	}()

	qtx := m.db.Queries.WithTx(tx)

	providerIdentity, err := qtx.GetIdentityByProviderAndProviderIdentifier(ctx, params)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return credential.Session{}, errors.Join(ErrCreatingSession, err)
		}
		// This identity doesn't exist, we need to create it
		if data.UserIdentifier == "" {
			// This identity is for a new user that we must create
			organizationName := "Personal Organization"
			if data.UserName != "" {
				organizationName = fmt.Sprintf("%s's Organization", data.UserName)
			}
			organizationIdentifier := uuid.New().String()
			organizationUUID, err := pgxtypes.UUIDFromString(organizationIdentifier)
			if err != nil {
				return credential.Session{}, errors.Join(ErrCreatingSession, err)
			}
			err = qtx.CreateOrganization(ctx, generated.CreateOrganizationParams{
				Identifier: organizationUUID,
				Name:       organizationName,
				IsDefault:  true,
			})
			if err != nil {
				return credential.Session{}, errors.Join(ErrCreatingSession, err)
			}
			userIdentifier := uuid.New().String()
			userUUID, err := pgxtypes.UUIDFromString(userIdentifier)
			if err != nil {
				return credential.Session{}, errors.Join(ErrCreatingSession, err)
			}
			err = qtx.CreateUser(ctx, generated.CreateUserParams{
				Identifier:                    userUUID,
				Name:                          data.UserName,
				PrimaryEmail:                  data.PrimaryEmail,
				DefaultOrganizationIdentifier: organizationUUID,
			})
			if err != nil {
				return credential.Session{}, errors.Join(ErrCreatingSession, err)
			}
			data.UserIdentifier = userIdentifier
		}

		// This identity must be associated with the given user
		dataUserUUID, err := pgxtypes.UUIDFromString(data.UserIdentifier)
		if err != nil {
			return credential.Session{}, errors.Join(ErrCreatingSession, err)
		}
		err = qtx.CreateIdentity(ctx, generated.CreateIdentityParams{
			Provider:           params.Provider,
			ProviderIdentifier: params.ProviderIdentifier,
			UserIdentifier:     dataUserUUID,
			VerifiedEmails:     verifiedEmails,
		})
		if err != nil {
			return credential.Session{}, errors.Join(ErrCreatingSession, err)
		}

		providerIdentity, err = qtx.GetIdentityByProviderAndProviderIdentifier(ctx, params)
		if err != nil {
			return credential.Session{}, errors.Join(ErrCreatingSession, err)
		}
	}

	user, err := qtx.GetUserByIdentifier(ctx, providerIdentity.UserIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	// Do not check if the last_login was updated, it will not get updated if
	// multiple sessions are created within the same second
	_, err = qtx.UpdateUserLastLoginByIdentifier(ctx, providerIdentity.UserIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	organization, err := qtx.GetOrganizationByIdentifier(ctx, user.DefaultOrganizationIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	sessionIdentifier := uuid.New().String()
	// PostgreSQL handles microsecond precision, no need to truncate
	expiresAt := time.Now().Add(m.Configuration().SessionExpiry())
	sessionUUID, err := pgxtypes.UUIDFromString(sessionIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	expiresAtTS, err := pgxtypes.TimestampFromTime(expiresAt)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	err = m.db.Queries.CreateSession(ctx, generated.CreateSessionParams{
		Identifier:             sessionUUID,
		OrganizationIdentifier: user.DefaultOrganizationIdentifier,
		UserIdentifier:         user.Identifier,
		Generation:             0,
		ExpiresAt:              expiresAtTS,
	})
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	session, err := m.db.Queries.GetSessionByIdentifier(ctx, sessionUUID)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	orgIdentifier, err := pgxtypes.StringFromUUID(session.OrganizationIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	userIdentifier, err := pgxtypes.StringFromUUID(session.UserIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	expiresAt, err = pgxtypes.TimeFromTimestamp(session.ExpiresAt)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	s := credential.Session{
		Identifier: sessionIdentifier,
		OrganizationInfo: credential.OrganizationInfo{
			Identifier: orgIdentifier,
			Name:       organization.Name,
			IsDefault:  true,
			Role:       role.OwnerRole,
		},
		UserInfo: credential.UserInfo{
			Identifier: userIdentifier,
			Name:       user.Name,
			Email:      user.PrimaryEmail,
		},
		Generation: uint32(session.Generation), //nolint:gosec // Generation is always non-negative
		ExpiresAt:  expiresAt,
	}

	if !s.IsValid() {
		return credential.Session{}, errors.Join(ErrCreatingSession, credential.ErrInvalidSession)
	}

	return s, nil
}

func (m *Manager) CreateExistingSession(ctx context.Context, identifier string) (credential.Session, error) {
	tx, err := m.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			m.logger.Error().Err(err).Str("session_identifier", identifier).Msg("failed to rollback transaction")
		}
	}()

	qtx := m.db.Queries.WithTx(tx)

	identifierUUID, err := pgxtypes.UUIDFromString(identifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	session, err := qtx.GetSessionByIdentifier(ctx, identifierUUID)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	user, err := qtx.GetUserByIdentifier(ctx, session.UserIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	organization, err := qtx.GetOrganizationByIdentifier(ctx, session.OrganizationIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	membership, err := qtx.GetMembershipByUserIdentifierAndOrganizationIdentifier(ctx, generated.GetMembershipByUserIdentifierAndOrganizationIdentifierParams{
		UserIdentifier:         session.UserIdentifier,
		OrganizationIdentifier: session.OrganizationIdentifier,
	})
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	membershipRole := role.Role(membership.Role)
	if !membershipRole.IsValid() {
		return credential.Session{}, errors.Join(ErrCreatingSession, ErrInvalidSessionRole)
	}

	sessionIdentifier, err := pgxtypes.StringFromUUID(session.Identifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	orgIdentifier, err := pgxtypes.StringFromUUID(session.OrganizationIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	userIdentifier, err := pgxtypes.StringFromUUID(session.UserIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}
	expiresAt, err := pgxtypes.TimeFromTimestamp(session.ExpiresAt)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	return credential.Session{
		Identifier: sessionIdentifier,
		OrganizationInfo: credential.OrganizationInfo{
			Identifier: orgIdentifier,
			Name:       organization.Name,
			IsDefault:  organization.IsDefault,
			Role:       membershipRole,
		},
		UserInfo: credential.UserInfo{
			Identifier: userIdentifier,
			Name:       user.Name,
			Email:      user.PrimaryEmail,
		},
		Generation: uint32(session.Generation), //nolint:gosec // Generation is always non-negative
		ExpiresAt:  expiresAt,
	}, nil
}

func (m *Manager) SignSession(session credential.Session) (string, error) {
	signingKey, _ := m.Configuration().SigningKey()
	return session.Sign(signingKey)
}

func (m *Manager) ParseSession(token string) (credential.Session, bool, error) {
	_, publicKey := m.Configuration().SigningKey()
	_, previousPublicKey := m.Configuration().PreviousSigningKey()
	return credential.ParseSession(token, publicKey, previousPublicKey)
}

func (m *Manager) RefreshSession(ctx context.Context, session credential.Session) (credential.Session, error) {
	now := time.Now()
	if session.ExpiresAt.Before(now) {
		return credential.Session{}, errors.Join(ErrRefreshingSession, ErrSessionIsExpired)
	}

	tx, err := m.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}

	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			m.logger.Error().Err(err).Str("session", session.Identifier).Msg("failed to rollback transaction")
		}
	}()

	qtx := m.db.Queries.WithTx(tx)

	sessionIdentifierUUID, err := pgxtypes.UUIDFromString(session.Identifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}
	s, err := qtx.GetSessionByIdentifier(ctx, sessionIdentifierUUID)
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}

	expiresAt, err := pgxtypes.TimeFromTimestamp(s.ExpiresAt)
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}
	if expiresAt.Before(now) {
		return credential.Session{}, errors.Join(ErrRefreshingSession, ErrSessionIsExpired)
	}

	if s.Generation != int32(session.Generation) { //nolint:gosec // Safe comparison
		session.Generation = uint32(s.Generation) //nolint:gosec // Generation is always non-negative

		userIdentifierUUID, err := pgxtypes.UUIDFromString(session.UserInfo.Identifier)
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}
		user, err := qtx.GetUserByIdentifier(ctx, userIdentifierUUID)
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}

		session.UserInfo.Name = user.Name
		session.UserInfo.Email = user.PrimaryEmail

		if !session.OrganizationInfo.IsDefault {
			// Not a default org, need to get the membership for updated role
			orgIdentifierUUID, err := pgxtypes.UUIDFromString(session.OrganizationInfo.Identifier)
			if err != nil {
				return credential.Session{}, errors.Join(ErrRefreshingSession, err)
			}
			membership, err := qtx.GetMembershipByUserIdentifierAndOrganizationIdentifier(ctx, generated.GetMembershipByUserIdentifierAndOrganizationIdentifierParams{
				UserIdentifier:         userIdentifierUUID,
				OrganizationIdentifier: orgIdentifierUUID,
			})
			if err != nil {
				return credential.Session{}, errors.Join(ErrRefreshingSession, err)
			}
			membershipRole := role.Role(membership.Role)
			if !membershipRole.IsValid() {
				return credential.Session{}, errors.Join(ErrRefreshingSession, ErrInvalidSessionRole)
			}
			session.OrganizationInfo.Role = membershipRole
		}

		orgIdentifierUUID2, err := pgxtypes.UUIDFromString(session.OrganizationInfo.Identifier)
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}
		organization, err := qtx.GetOrganizationByIdentifier(ctx, orgIdentifierUUID2)
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}
		session.OrganizationInfo.Name = organization.Name
	}

	// PostgreSQL handles microsecond precision, no need to truncate
	session.ExpiresAt = time.Now().Add(m.Configuration().SessionExpiry())
	currentExpiresAt, err := pgxtypes.TimeFromTimestamp(s.ExpiresAt)
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}
	if session.ExpiresAt.After(currentExpiresAt) {
		expiresAtTS, err := pgxtypes.TimestampFromTime(session.ExpiresAt)
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}
		num, err := qtx.UpdateSessionExpiryByIdentifier(ctx, generated.UpdateSessionExpiryByIdentifierParams{
			ExpiresAt:  expiresAtTS,
			Identifier: sessionIdentifierUUID,
		})
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}
		if num == 0 {
			return credential.Session{}, errors.Join(ErrRefreshingSession, sql.ErrNoRows)
		}
	} else {
		session.ExpiresAt = currentExpiresAt
	}

	err = tx.Commit(ctx)
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}

	return session, nil
}

func (m *Manager) RevokeSession(ctx context.Context, identifier string) error {
	tx, err := m.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}

	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			m.logger.Error().Err(err).Str("session", identifier).Msg("failed to rollback transaction")
		}
	}()

	qtx := m.db.Queries.WithTx(tx)

	identifierUUID, err := pgxtypes.UUIDFromString(identifier)
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}
	session, err := qtx.GetSessionByIdentifier(ctx, identifierUUID)
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}

	num, err := qtx.DeleteSessionByIdentifier(ctx, session.Identifier)
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}
	if num == 0 {
		return errors.Join(ErrRevokingSession, sql.ErrNoRows)
	}

	expiresAt, err := pgxtypes.TimeFromTimestamp(session.ExpiresAt)
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}
	expiresAtWithJitterTS, err := pgxtypes.TimestampFromTime(expiresAt.Add(Jitter))
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}
	err = qtx.CreateSessionRevocation(ctx, generated.CreateSessionRevocationParams{
		SessionIdentifier: session.Identifier,
		ExpiresAt:         expiresAtWithJitterTS,
	})
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}

	return nil
}

func (m *Manager) SessionRevocationList() []string {
	return m.sessionRevocationCache.Keys()
}

func (m *Manager) SessionInvalidationList() []InvalidatedSession {
	items := m.sessionInvalidationCache.Items()
	sessions := make([]InvalidatedSession, 0, len(items))
	for _, item := range items {
		sessions = append(sessions, InvalidatedSession{
			Identifier: item.Key(),
			Generation: item.Value(),
		})
	}
	return sessions
}

func (m *Manager) IsSessionRevoked(identifier string) bool {
	return m.sessionRevocationCache.Get(identifier, ttlcache.WithDisableTouchOnHit[string, struct{}]()) != nil
}

func (m *Manager) IsSessionInvalidated(identifier string, generation uint32) bool {
	item := m.sessionInvalidationCache.Get(identifier, ttlcache.WithDisableTouchOnHit[string, uint32]())
	if item == nil {
		return false
	}
	return item.Value() >= generation
}

func (m *Manager) ValidateSession(ctx context.Context, token string) (credential.Session, bool, error) {
	_, publicKey := m.Configuration().SigningKey()
	_, previousPublicKey := m.Configuration().PreviousSigningKey()
	session, reSign, err := credential.ParseSession(token, publicKey, previousPublicKey)
	if err != nil {
		return credential.Session{}, false, errors.Join(ErrValidatingSession, err)
	}
	if m.IsSessionRevoked(session.Identifier) {
		return credential.Session{}, false, errors.Join(ErrValidatingSession, ErrRevokedSession)
	}
	if m.IsSessionInvalidated(session.Identifier, session.Generation) || (m.Configuration().SessionExpiry() > ForcedRefresh && session.ExpiresAt.Before(time.Now().Add(ForcedRefresh))) {
		m.logger.Debug().Str("session", session.Identifier).Msg("session invalidated, refreshing")
		session, err = m.RefreshSession(ctx, session)
		if err != nil {
			return credential.Session{}, false, errors.Join(ErrValidatingSession, err)
		}
		reSign = true
	}
	return session, reSign, nil
}

func (m *Manager) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy && m.sessionRevocationHealthy && m.sessionInvalidationHealthy
}

func (m *Manager) Database() *db.DB {
	return m.db
}

func (m *Manager) Close() error {
	m.cancel()
	m.wg.Wait()

	err := m.configuration.Close()
	if err != nil {
		return err
	}

	if m.github != nil {
		err = m.github.Close()
		if err != nil {
			return err
		}
	}

	if m.google != nil {
		err = m.google.Close()
		if err != nil {
			return err
		}
	}

	if m.magic != nil {
		err = m.magic.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) sessionGC() (int64, error) {
	ctx, cancel := context.WithTimeout(m.ctx, Timeout)
	defer cancel()
	return m.db.Queries.DeleteExpiredSessions(ctx)
}

func (m *Manager) doSessionGC() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("session GC stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := m.sessionGC()
			if err != nil {
				m.logger.Error().Err(err).Msg("failed to garbage collect expired sessions")
			} else {
				m.logger.Debug().Msgf("garbage collected %d expired sessions", deleted)
			}
		}
	}
}

func (m *Manager) sessionRevocationGC() (int64, error) {
	ctx, cancel := context.WithTimeout(m.ctx, Timeout)
	defer cancel()
	return m.db.Queries.DeleteExpiredSessionRevocations(ctx)
}

func (m *Manager) doSessionRevocationGC() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("session revocation GC stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := m.sessionRevocationGC()
			if err != nil {
				m.logger.Error().Err(err).Msg("failed to garbage collect expired session revocations")
			} else {
				m.logger.Debug().Msgf("garbage collected %d expired session revocations", deleted)
			}
		}
	}
}

func (m *Manager) sessionRevocationsRefresh() {
	m.sessionRevocationCache.DeleteExpired()
	ctx, cancel := context.WithTimeout(m.ctx, Timeout)
	defer cancel()
	refreshed := 0
	sessionRevocations, err := m.db.Queries.GetAllSessionRevocations(ctx)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to update session revocations")
		m.mu.Lock()
		m.sessionRevocationHealthy = false
		m.mu.Unlock()
	} else {
		for _, sessionRevocation := range sessionRevocations {
			expiresAt, err := pgxtypes.TimeFromTimestamp(sessionRevocation.ExpiresAt)
			if err != nil {
				m.logger.Error().Err(err).Msg("failed to parse session revocation expiry")
				continue
			}
			if expiresAt.After(time.Now()) {
				identifier, err := pgxtypes.StringFromUUID(sessionRevocation.SessionIdentifier)
				if err != nil {
					m.logger.Error().Err(err).Msg("failed to parse session revocation identifier")
					continue
				}
				m.sessionRevocationCache.Set(identifier, struct{}{}, time.Until(expiresAt))
				refreshed++
			}
		}
		m.logger.Debug().Msgf("refresh %d session revocations", refreshed)
		m.mu.Lock()
		m.sessionRevocationHealthy = true
		m.mu.Unlock()
	}
}

func (m *Manager) sessionInvalidationsRefresh() {
	m.sessionInvalidationCache.DeleteExpired()
	ctx, cancel := context.WithTimeout(m.ctx, Timeout)
	defer cancel()
	refreshed := 0
	sessionInvalidations, err := m.db.Queries.GetAllSessionInvalidations(ctx)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to update session invalidations")
		m.mu.Lock()
		m.sessionInvalidationHealthy = false
		m.mu.Unlock()
	} else {
		for _, sessionInvalidation := range sessionInvalidations {
			expiresAt, err := pgxtypes.TimeFromTimestamp(sessionInvalidation.ExpiresAt)
			if err != nil {
				m.logger.Error().Err(err).Msg("failed to parse session invalidation expiry")
				continue
			}
			if expiresAt.After(time.Now()) {
				identifier, err := pgxtypes.StringFromUUID(sessionInvalidation.SessionIdentifier)
				if err != nil {
					m.logger.Error().Err(err).Msg("failed to parse session invalidation identifier")
					continue
				}
				m.sessionInvalidationCache.Set(identifier, uint32(sessionInvalidation.Generation), time.Until(expiresAt)) //nolint:gosec // Generation is always non-negative
				refreshed++
			}
		}
		m.logger.Debug().Msgf("refresh %d session invalidations", refreshed)
		m.mu.Lock()
		m.sessionInvalidationHealthy = true
		m.mu.Unlock()
	}
}

func (m *Manager) doRefresh() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("refresh stopped")
			return
		case <-time.After(m.Configuration().PollInterval()):
			m.sessionRevocationsRefresh()
			m.sessionInvalidationsRefresh()
		}
	}
}

func (m *Manager) healthCheck() {
	m.mu.Lock()
	m.healthy = m.db.DB.PingContext(m.ctx) == nil &&
		m.configuration.IsHealthy() &&
		(m.mailer == nil || m.mailer.TestConnection(m.ctx) == nil)
	m.mu.Unlock()
}

func (m *Manager) doHealthCheck() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("health check stopped")
			return
		case <-time.After(HealthInterval):
			m.healthCheck()
		}
	}
}
