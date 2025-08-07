//SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/mailer"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/manager/flow"
	"github.com/loopholelabs/auth/pkg/manager/flow/github"
	"github.com/loopholelabs/auth/pkg/manager/flow/google"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
)

var (
	ErrCreatingManager = errors.New("error creating manager")
	ErrCreatingSession = errors.New("error creating session")
	ErrInvalidProvider = errors.New("invalid provider")
	ErrInvalidFlowData = errors.New("invalid flow data")
)

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
	Github GithubOptions
	Google GoogleOptions
	Magic  MagicOptions
	Mailer MailerOptions
}

type Session struct {
	Session generated.Session
}

type Manager struct {
	logger types.Logger
	db     *db.DB

	github *github.Github
	google *google.Google
	magic  *magic.Magic

	mailer mailer.Mailer
}

func New(options Options, db *db.DB, logger types.Logger) (*Manager, error) {
	logger = logger.SubLogger("MANAGER")

	var err error
	var gh *github.Github
	if options.Github.Enabled {
		gh, err = github.New(github.Options{
			RedirectURL:  "",
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
			RedirectURL:  "",
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

	return &Manager{
		logger: logger,
		db:     db,
		github: gh,
		google: gg,
		magic:  mg,
		mailer: ml,
	}, nil
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
		_ = tx.Rollback()
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
			organizationName := fmt.Sprintf("%s Organization", utils.RandomString(16))
			if data.Name != "" {
				organizationName = fmt.Sprintf("%s's Organization", data.Name)
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
		ExpiresAt:              time.Now().Add(time.Minute * 30),
	})
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
	}

	session, err := m.db.Queries.GetSessionByIdentifier(ctx, sessionIdentifier)
	if err != nil {
		return nil, errors.Join(ErrCreatingSession, err)
	}

	return &Session{
		Session: session,
	}, nil
}
