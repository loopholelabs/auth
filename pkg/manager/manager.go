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
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/flow/github"
	"github.com/loopholelabs/auth/pkg/manager/flow/google"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
	"github.com/loopholelabs/auth/pkg/manager/role"
)

const (
	Timeout = time.Second * 30
)

var (
	ErrCreatingManager = errors.New("error creating manager")
	ErrDBIsRequired    = errors.New("db is required")
	ErrCreatingSession = errors.New("error creating session")
	ErrInvalidProvider = errors.New("invalid provider")
	ErrInvalidFlowData = errors.New("invalid flow data")
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

type Options struct {
	Github        GithubOptions
	Google        GoogleOptions
	Magic         MagicOptions
	Mailer        MailerOptions
	Configuration configuration.Options
}

type Manager struct {
	logger types.Logger
	db     *db.DB

	configuration *configuration.Configuration

	github *github.Github
	google *google.Google
	magic  *magic.Magic

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

	m := &Manager{
		logger:        logger,
		db:            db,
		configuration: c,
		github:        gh,
		google:        gg,
		magic:         mg,
		mailer:        ml,
	}

	// m.wg.Add(1)
	// go m.doGC()

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

func (m *Manager) CreateSession(ctx context.Context, data flow.Data, provider flow.Provider) (*Session, error) {
	if data.ProviderIdentifier == "" {
		return nil, errors.Join(ErrCreatingSession, ErrInvalidFlowData)
	}
	if len(data.VerifiedEmails) < 1 {
		return nil, errors.Join(ErrCreatingSession, ErrInvalidFlowData)
	}
	verifiedEmails, err := json.Marshal(data.VerifiedEmails)
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
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
		return nil, errors.Join(ErrCreatingSession, ErrInvalidProvider)
	}

	tx, err := m.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
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
			return nil, errors.Join(ErrCreatingSession, err)
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
				return nil, errors.Join(ErrCreatingSession, err)
			}
			userIdentifier := uuid.New().String()
			err = qtx.CreateUser(ctx, generated.CreateUserParams{
				Identifier:                    userIdentifier,
				Name:                          data.UserName,
				PrimaryEmail:                  data.PrimaryEmail,
				DefaultOrganizationIdentifier: organizationIdentifier,
			})
			if err != nil {
				return nil, errors.Join(ErrCreatingSession, err)
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
			return nil, errors.Join(ErrCreatingSession, err)
		}

		providerIdentity, err = qtx.GetIdentityByProviderAndProviderIdentifier(ctx, params)
		if err != nil {
			return nil, errors.Join(ErrCreatingSession, err)
		}
	}

	user, err := qtx.GetUserByIdentifier(ctx, providerIdentity.UserIdentifier)
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
	}

	sessionIdentifier := uuid.New().String()
	err = m.db.Queries.CreateSession(ctx, generated.CreateSessionParams{
		Identifier:             sessionIdentifier,
		OrganizationIdentifier: user.DefaultOrganizationIdentifier,
		UserIdentifier:         user.Identifier,
		LastGeneration:         0,
		ExpiresAt:              time.Now().Add(m.configuration.SessionExpiry()),
	})
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
	}

	session, err := m.db.Queries.GetSessionByIdentifier(ctx, sessionIdentifier)
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
	}

	return &Session{
		Identifier: sessionIdentifier,
		OrganizationInfo: OrganizationInfo{
			Identifier: session.OrganizationIdentifier,
			Role:       role.OwnerRole.String(),
		},
		UserInfo: UserInfo{
			Identifier: session.UserIdentifier,
			Name:       user.Name,
			Email:      user.PrimaryEmail,
		},
		Generation: session.LastGeneration,
		ExpiresAt:  session.ExpiresAt,
	}, nil
}

// func (c *Manager) gc() (int64, error) {
//	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
//	defer cancel()
//	return c.db.Queries.DeleteGithubOAuthFlowsBeforeTime(ctx, now().Add(-Expiry))
//}
//
// func (c *Manager) doGC() {
//	defer c.wg.Done()
//	for {
//		select {
//		case <-c.ctx.Done():
//			c.logger.Info().Msg("GC Stopped")
//			return
//		case <-time.After(GCInterval):
//			deleted, err := c.gc()
//			if err != nil {
//				c.logger.Error().Err(err).Msg("failed to garbage collect expired flows")
//			} else {
//				c.logger.Debug().Msgf("garbage collected %d expired flows", deleted)
//			}
//		}
//	}
//}
