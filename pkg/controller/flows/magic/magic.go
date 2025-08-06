//SPDX-License-Identifier: Apache-2.0

package magic

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/pkg/controller/flows"
)

var (
	ErrDBIsRequired   = errors.New("db is required")
	ErrCreatingFlow   = errors.New("error creating flow")
	ErrCompletingFlow = errors.New("error completing flow")
	ErrInvalidToken   = errors.New("invalid token")
	ErrInvalidSecret  = errors.New("invalid secret")
)

var (
	now = time.Now
)

const (
	GCInterval = time.Minute
	Expiry     = time.Minute * 5
	Timeout    = time.Second * 30
)

type Magic struct {
	logger types.Logger
	db     *db.DB

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func New(db *db.DB, logger types.Logger) (*Magic, error) {
	if db == nil {
		return nil, ErrDBIsRequired
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &Magic{
		logger: logger.SubLogger("MAGIC"),
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}

	g.wg.Add(1)
	go g.doGC()

	return g, nil
}

func (c *Magic) Close() error {
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *Magic) CreateFlow(ctx context.Context, emailAddress string, deviceIdentifier string, userIdentifier string, nextURL string) (string, error) {
	salt := uuid.New().String()
	secret := uuid.New().String()
	hash, err := bcrypt.GenerateFromPassword(append([]byte(salt), []byte(secret)...), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Join(ErrCreatingFlow, err)
	}

	params := generated.CreateMagicLinkFlowParams{
		Identifier:   uuid.New().String(),
		Salt:         salt,
		Hash:         hash,
		EmailAddress: emailAddress,
		DeviceIdentifier: sql.NullString{
			String: deviceIdentifier,
			Valid:  deviceIdentifier != "",
		},
		UserIdentifier: sql.NullString{
			String: userIdentifier,
			Valid:  userIdentifier != "",
		},
		NextUrl: sql.NullString{
			String: nextURL,
			Valid:  nextURL != "",
		},
	}

	c.logger.Debug().Msg("creating flow")
	err = c.db.Queries.CreateMagicLinkFlow(ctx, params)
	if err != nil {
		return "", errors.Join(ErrCreatingFlow, err)
	}

	return base64.StdEncoding.EncodeToString([]byte(params.Identifier + "_" + secret)), nil
}

func (c *Magic) CompleteFlow(ctx context.Context, token string) (*flows.Flow, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.Join(ErrCompletingFlow, ErrInvalidToken, err)
	}

	identifierBytes := tokenBytes[:bytes.IndexByte(tokenBytes, '_')]
	identifier := string(identifierBytes)
	if len(identifier) != 36 {
		return nil, errors.Join(ErrCompletingFlow, ErrInvalidToken)
	}

	secretBytes := tokenBytes[bytes.IndexByte(tokenBytes, '_')+1:]
	secret := string(secretBytes)
	if len(secret) != 36 {
		return nil, errors.Join(ErrCompletingFlow, ErrInvalidToken)
	}

	c.logger.Debug().Str("identifier", identifier).Msg("completing flow")
	flow, err := c.db.Queries.GetMagicLinkFlowByIdentifier(ctx, identifier)
	if err != nil {
		return nil, errors.Join(ErrCompletingFlow, err)
	}

	err = c.db.Queries.DeleteMagicLinkFlowByIdentifier(ctx, identifier)
	if err != nil {
		return nil, errors.Join(ErrCompletingFlow, err)
	}

	if bcrypt.CompareHashAndPassword(flow.Hash, append([]byte(flow.Salt), []byte(secret)...)) != nil {
		return nil, errors.Join(ErrCompletingFlow, ErrInvalidSecret)
	}

	return &flows.Flow{
		Identifier:       flow.EmailAddress,
		Name:             "",
		NextURL:          flow.NextUrl.String,
		DeviceIdentifier: flow.DeviceIdentifier.String,
		UserIdentifier:   flow.UserIdentifier.String,
		PrimaryEmail:     flow.EmailAddress,
		VerifiedEmails:   []string{flow.EmailAddress},
	}, nil
}

func (c *Magic) gc() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	return c.db.Queries.DeleteMagicLinkFlowsBeforeTime(ctx, now().Add(-Expiry))
}

func (c *Magic) doGC() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			c.logger.Info().Msg("GC Stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := c.gc()
			if err != nil {
				c.logger.Error().Err(err).Msg("failed to garbage collect expired flows")
			} else {
				c.logger.Debug().Msgf("garbage collected %d expired flows", deleted)
			}
		}
	}
}
