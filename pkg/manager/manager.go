//SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/mailer"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
	"github.com/loopholelabs/auth/pkg/manager/credential"
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/flow/device"
	"github.com/loopholelabs/auth/pkg/manager/flow/github"
	"github.com/loopholelabs/auth/pkg/manager/flow/google"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
	"github.com/loopholelabs/auth/pkg/manager/role"
)

const (
	Timeout    = time.Second * 30
	GCInterval = time.Minute
	Jitter     = time.Second * 5
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
)

type GithubOptions struct {
	Enabled      bool
	RedirectURL  string
	ClientID     string
	ClientSecret string
}

type GoogleOptions struct {
	Enabled      bool
	RedirectURL  string
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

type TokenOptions struct {
	Issuer string
}

type Options struct {
	Github        GithubOptions
	Google        GoogleOptions
	Magic         MagicOptions
	Device        DeviceOptions
	Mailer        MailerOptions
	Configuration configuration.Options
	Token         TokenOptions
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

	var gh *github.Github
	if options.Github.Enabled {
		gh, err = github.New(github.Options{
			RedirectURL:  options.Github.RedirectURL,
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
			RedirectURL:  options.Google.RedirectURL,
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

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		logger:        logger,
		db:            db,
		configuration: c,
		github:        gh,
		google:        gg,
		magic:         mg,
		device:        dv,
		mailer:        ml,
		ctx:           ctx,
		cancel:        cancel,
	}

	m.wg.Add(1)
	go m.doSessionGC()

	m.wg.Add(1)
	go m.doSessionRevocationGC()

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
		params.Provider = generated.IdentitiesProviderGITHUB
	case flow.GoogleProvider:
		params.Provider = generated.IdentitiesProviderGOOGLE
	case flow.MagicProvider:
		params.Provider = generated.IdentitiesProviderMAGIC
	default:
		return credential.Session{}, errors.Join(ErrCreatingSession, ErrInvalidProvider)
	}

	tx, err := m.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
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
			err = qtx.CreateOrganization(ctx, generated.CreateOrganizationParams{
				Identifier: organizationIdentifier,
				Name:       organizationName,
				IsDefault:  true,
			})
			if err != nil {
				return credential.Session{}, errors.Join(ErrCreatingSession, err)
			}
			userIdentifier := uuid.New().String()
			err = qtx.CreateUser(ctx, generated.CreateUserParams{
				Identifier:                    userIdentifier,
				Name:                          data.UserName,
				PrimaryEmail:                  data.PrimaryEmail,
				DefaultOrganizationIdentifier: organizationIdentifier,
			})
			if err != nil {
				return credential.Session{}, errors.Join(ErrCreatingSession, err)
			}
			data.UserIdentifier = userIdentifier
		}
		// This identity must be associated with the given user
		err = qtx.CreateIdentity(ctx, generated.CreateIdentityParams{
			Provider:           params.Provider,
			ProviderIdentifier: params.ProviderIdentifier,
			UserIdentifier:     data.UserIdentifier,
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

	err = tx.Commit()
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	sessionIdentifier := uuid.New().String()
	// Truncate expiry time to nearest second to match MySQL DATETIME precision
	// This ensures consistency between Go's nanosecond precision and MySQL's second precision
	expiresAt := time.Now().Add(m.Configuration().SessionExpiry()).Truncate(time.Second)
	err = m.db.Queries.CreateSession(ctx, generated.CreateSessionParams{
		Identifier:             sessionIdentifier,
		OrganizationIdentifier: user.DefaultOrganizationIdentifier,
		UserIdentifier:         user.Identifier,
		Generation:             0,
		ExpiresAt:              expiresAt,
	})
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	session, err := m.db.Queries.GetSessionByIdentifier(ctx, sessionIdentifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	s := credential.Session{
		Identifier: sessionIdentifier,
		OrganizationInfo: credential.OrganizationInfo{
			Identifier: session.OrganizationIdentifier,
			IsDefault:  true,
			Role:       role.OwnerRole,
		},
		UserInfo: credential.UserInfo{
			Identifier: session.UserIdentifier,
			Name:       user.Name,
			Email:      user.PrimaryEmail,
		},
		Generation: session.Generation,
		ExpiresAt:  session.ExpiresAt,
	}

	if !s.IsValid() {
		return credential.Session{}, errors.Join(ErrCreatingSession, credential.ErrInvalidSession)
	}

	return s, nil
}

func (m *Manager) CreateExistingSession(ctx context.Context, identifier string) (credential.Session, error) {
	tx, err := m.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			m.logger.Error().Err(err).Str("session_identifier", identifier).Msg("failed to rollback transaction")
		}
	}()

	qtx := m.db.Queries.WithTx(tx)

	session, err := qtx.GetSessionByIdentifier(ctx, identifier)
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

	err = tx.Commit()
	if err != nil {
		return credential.Session{}, errors.Join(ErrCreatingSession, err)
	}

	membershipRole := role.Role(membership.Role)
	if !membershipRole.IsValid() {
		return credential.Session{}, errors.Join(ErrCreatingSession, ErrInvalidSessionRole)
	}

	return credential.Session{
		Identifier: session.Identifier,
		OrganizationInfo: credential.OrganizationInfo{
			Identifier: session.OrganizationIdentifier,
			IsDefault:  organization.IsDefault,
			Role:       membershipRole,
		},
		UserInfo: credential.UserInfo{
			Identifier: session.UserIdentifier,
			Name:       user.Name,
			Email:      user.PrimaryEmail,
		},
		Generation: session.Generation,
		ExpiresAt:  session.ExpiresAt,
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

	tx, err := m.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			m.logger.Error().Err(err).Str("session", session.Identifier).Msg("failed to rollback transaction")
		}
	}()

	qtx := m.db.Queries.WithTx(tx)

	s, err := qtx.GetSessionByIdentifier(ctx, session.Identifier)
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}

	if s.ExpiresAt.Before(now) {
		return credential.Session{}, errors.Join(ErrRefreshingSession, ErrSessionIsExpired)
	}

	if s.Generation != session.Generation {
		session.Generation = s.Generation

		user, err := qtx.GetUserByIdentifier(ctx, session.UserInfo.Identifier)
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}

		session.UserInfo.Name = user.Name
		session.UserInfo.Email = user.PrimaryEmail

		if !session.OrganizationInfo.IsDefault {
			// Not a default org, need to get the membership for updated role
			membership, err := qtx.GetMembershipByUserIdentifierAndOrganizationIdentifier(ctx, generated.GetMembershipByUserIdentifierAndOrganizationIdentifierParams{
				UserIdentifier:         session.UserInfo.Identifier,
				OrganizationIdentifier: session.OrganizationInfo.Identifier,
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
	}

	// Truncate expiry time to nearest second to match MySQL DATETIME precision
	// This ensures consistency between Go's nanosecond precision and MySQL's second precision
	session.ExpiresAt = time.Now().Add(m.Configuration().SessionExpiry()).Truncate(time.Second)
	if session.ExpiresAt.After(s.ExpiresAt) {
		num, err := qtx.UpdateSessionExpiryByIdentifier(ctx, generated.UpdateSessionExpiryByIdentifierParams{
			ExpiresAt:  session.ExpiresAt,
			Identifier: session.Identifier,
		})
		if err != nil {
			return credential.Session{}, errors.Join(ErrRefreshingSession, err)
		}
		if num == 0 {
			return credential.Session{}, errors.Join(ErrRefreshingSession, sql.ErrNoRows)
		}
	} else {
		session.ExpiresAt = s.ExpiresAt
	}

	err = tx.Commit()
	if err != nil {
		return credential.Session{}, errors.Join(ErrRefreshingSession, err)
	}

	return session, nil
}

func (m *Manager) RevokeSession(ctx context.Context, identifier string) error {
	tx, err := m.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			m.logger.Error().Err(err).Str("session", identifier).Msg("failed to rollback transaction")
		}
	}()

	qtx := m.db.Queries.WithTx(tx)

	session, err := qtx.GetSessionByIdentifier(ctx, identifier)
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

	err = qtx.CreateSessionRevocation(ctx, generated.CreateSessionRevocationParams{
		SessionIdentifier: session.Identifier,
		ExpiresAt:         session.ExpiresAt.Add(Jitter),
	})
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}

	err = tx.Commit()
	if err != nil {
		return errors.Join(ErrRevokingSession, err)
	}

	return nil
}

func (m *Manager) Healthy() bool {
	return m.db.DB.PingContext(m.ctx) == nil && m.configuration.IsHealthy() && (m.mailer == nil || m.mailer.TestConnection(m.ctx) == nil)
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
			m.logger.Info().Msg("Session GC Stopped")
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
			m.logger.Info().Msg("Session Revocation GC Stopped")
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
