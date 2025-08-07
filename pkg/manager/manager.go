//SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/mailer"
	"github.com/loopholelabs/auth/pkg/manager/flow/github"
	"github.com/loopholelabs/auth/pkg/manager/flow/google"
	"github.com/loopholelabs/auth/pkg/manager/flow/magic"
)

var (
	ErrCreatingManager = errors.New("error creating manager")
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
