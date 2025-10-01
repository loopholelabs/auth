//SPDX-License-Identifier: Apache-2.0

package magic

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/db/pgxtypes"
	"github.com/loopholelabs/auth/pkg/manager/flow"
)

var (
	ErrDBIsRequired   = errors.New("db is required")
	ErrCreatingFlow   = errors.New("error creating flow")
	ErrCompletingFlow = errors.New("error completing flow")
	ErrInvalidNextURL = errors.New("invalid next URL")
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

// CreateFlow creates a new magic link flow
// Called from API handler - inputs should be pre-validated pgx types
// Defensive check: validates deviceIdentifier.Valid and userIdentifier.Valid if provided
// Note: emailAddress and nextURL are strings (not database IDs)
func (c *Magic) CreateFlow(ctx context.Context, emailAddress string, deviceIdentifier pgtype.UUID, userIdentifier pgtype.UUID, nextURL string) (string, error) {
	// Defensive validation - should never fail if API handler validated properly
	// Note: These can be invalid (Valid: false) if not provided
	if deviceIdentifier.Valid && deviceIdentifier.Bytes == [16]byte{} {
		c.logger.Error().Msg("CreateFlow called with valid but empty device identifier - API handler validation failed")
		return "", errors.Join(ErrCreatingFlow, errors.New("invalid device identifier"))
	}
	if userIdentifier.Valid && userIdentifier.Bytes == [16]byte{} {
		c.logger.Error().Msg("CreateFlow called with valid but empty user identifier - API handler validation failed")
		return "", errors.Join(ErrCreatingFlow, errors.New("invalid user identifier"))
	}

	if nextURL == "" {
		return "", errors.Join(ErrCreatingFlow, ErrInvalidNextURL)
	}
	salt := uuid.New().String()
	secret := uuid.New().String()
	h := hmac.New(sha256.New, []byte(salt))
	h.Write([]byte(secret))
	hash := h.Sum(nil)

	identifierStr := uuid.New().String()
	var err error

	identifier, err := pgxtypes.UUIDFromString(identifierStr)
	if err != nil {
		return "", errors.Join(ErrCreatingFlow, err)
	}
	saltUUID, err := pgxtypes.UUIDFromString(salt)
	if err != nil {
		return "", errors.Join(ErrCreatingFlow, err)
	}
	params := generated.CreateMagicLinkFlowParams{
		Identifier:       identifier,
		Salt:             saltUUID,
		Hash:             hash,
		EmailAddress:     emailAddress,
		DeviceIdentifier: deviceIdentifier,
		UserIdentifier:   userIdentifier,
		NextUrl:          nextURL,
	}

	c.logger.Debug().Msg("creating flow")
	err = c.db.Queries.CreateMagicLinkFlow(ctx, params)
	if err != nil {
		return "", errors.Join(ErrCreatingFlow, err)
	}

	return base64.StdEncoding.EncodeToString([]byte(identifierStr + "_" + secret)), nil
}

func (c *Magic) CompleteFlow(ctx context.Context, token string) (flow.Data, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, ErrInvalidToken, err)
	}

	underscoreIndex := bytes.IndexByte(tokenBytes, '_')
	if underscoreIndex == -1 {
		return flow.Data{}, errors.Join(ErrCompletingFlow, ErrInvalidToken)
	}

	identifierBytes := tokenBytes[:underscoreIndex]
	identifier := string(identifierBytes)
	if len(identifier) != 36 {
		return flow.Data{}, errors.Join(ErrCompletingFlow, ErrInvalidToken)
	}

	secretBytes := tokenBytes[underscoreIndex+1:]
	secret := string(secretBytes)
	if len(secret) != 36 {
		return flow.Data{}, errors.Join(ErrCompletingFlow, ErrInvalidToken)
	}

	c.logger.Debug().Str("identifier", identifier).Msg("completing flow")
	tx, err := c.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			c.logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()

	qtx := c.db.Queries.WithTx(tx)

	identifierUUID, err := pgxtypes.UUIDFromString(identifier)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	f, err := qtx.GetMagicLinkFlowByIdentifier(ctx, identifierUUID)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	num, err := qtx.DeleteMagicLinkFlowByIdentifier(ctx, identifierUUID)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}
	if num == 0 {
		return flow.Data{}, errors.Join(ErrCompletingFlow, sql.ErrNoRows)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	saltStr, err := pgxtypes.StringFromUUID(f.Salt)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}
	h := hmac.New(sha256.New, []byte(saltStr))
	h.Write([]byte(secret))
	if !hmac.Equal(f.Hash, h.Sum(nil)) {
		return flow.Data{}, errors.Join(ErrCompletingFlow, ErrInvalidSecret)
	}

	deviceIdentifier, _ := pgxtypes.StringFromUUID(f.DeviceIdentifier) // OK if empty
	userIdentifier, _ := pgxtypes.StringFromUUID(f.UserIdentifier)     // OK if empty

	return flow.Data{
		ProviderIdentifier: f.EmailAddress,
		UserName:           "",
		NextURL:            f.NextUrl,
		DeviceIdentifier:   deviceIdentifier,
		UserIdentifier:     userIdentifier,
		PrimaryEmail:       f.EmailAddress,
		VerifiedEmails:     []string{f.EmailAddress},
	}, nil
}

func (c *Magic) gc() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	ts, err := pgxtypes.TimestampFromTime(now().Add(-Expiry))
	if err != nil {
		return 0, err
	}
	return c.db.Queries.DeleteMagicLinkFlowsBeforeCreatedAt(ctx, ts)
}

func (c *Magic) doGC() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			c.logger.Debug().Msg("GC stopped")
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
