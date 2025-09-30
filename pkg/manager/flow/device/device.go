//SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"database/sql"
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
	"github.com/loopholelabs/auth/internal/utils"
)

var (
	ErrDBIsRequired     = errors.New("db is required")
	ErrCreatingFlow     = errors.New("error creating flow")
	ErrPollingFlow      = errors.New("error polling flow")
	ErrGettingFlow      = errors.New("error getting flow")
	ErrCompletingFlow   = errors.New("error completing flow")
	ErrRateLimitFlow    = errors.New("error rate limit")
	ErrFlowNotCompleted = errors.New("flow not completed")
)

var (
	now = time.Now
)

const (
	GCInterval = time.Minute
	Expiry     = time.Minute * 5
	Timeout    = time.Second * 30
)

type Device struct {
	logger types.Logger
	db     *db.DB

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func New(db *db.DB, logger types.Logger) (*Device, error) {
	if db == nil {
		return nil, ErrDBIsRequired
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &Device{
		logger: logger.SubLogger("DEVICE"),
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}

	g.wg.Add(1)
	go g.doGC()

	return g, nil
}

func (c *Device) Close() error {
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *Device) CreateFlow(ctx context.Context) (string, string, error) {
	code := utils.RandomBase32String(8)
	poll := uuid.New().String()
	identifier, err := pgxtypes.NewUUID()
	if err != nil {
		return "", "", errors.Join(ErrCreatingFlow, err)
	}
	pollUUID, err := pgxtypes.UUIDFromString(poll)
	if err != nil {
		return "", "", errors.Join(ErrCreatingFlow, err)
	}
	params := generated.CreateDeviceCodeFlowParams{
		Identifier: identifier,
		Code:       code,
		Poll:       pollUUID,
	}

	c.logger.Debug().Msg("creating flow")
	err = c.db.Queries.CreateDeviceCodeFlow(ctx, params)
	if err != nil {
		return "", "", errors.Join(ErrCreatingFlow, err)
	}

	return code, poll, nil
}

func (c *Device) ExistsFlow(ctx context.Context, code string) (string, error) {
	c.logger.Debug().Msg("checking if flow exists")
	f, err := c.db.Queries.GetDeviceCodeFlowByCode(ctx, code)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", errors.Join(ErrGettingFlow, err)
		}
		return "", nil
	}
	identifier, err := pgxtypes.StringFromUUID(f.Identifier)
	if err != nil {
		return "", errors.Join(ErrGettingFlow, err)
	}
	return identifier, nil
}

// PollFlow checks if a device code flow has been completed
// Called from API handler - inputs should be pre-validated pgx types
// Defensive check: validates poll.Valid (returns error → 500 if invalid)
func (c *Device) PollFlow(ctx context.Context, poll pgtype.UUID, pollRate time.Duration) (string, error) {
	// Defensive validation - should never fail if API handler validated properly
	if !poll.Valid {
		c.logger.Error().Msg("PollFlow called with invalid poll UUID - API handler validation failed")
		return "", errors.Join(ErrPollingFlow, errors.New("invalid poll identifier"))
	}

	pollStr, _ := pgxtypes.StringFromUUID(poll)
	c.logger.Debug().Str("poll", pollStr).Msg("polling flow")
	tx, err := c.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
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

	f, err := qtx.GetDeviceCodeFlowByPoll(ctx, poll)
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}

	// Check polling rate limit (skip for first poll when last_poll == created_at)
	// Both timestamps use DEFAULT CURRENT_TIMESTAMP, so they're equal on first poll
	lastPollTime, err := pgxtypes.TimeFromTimestamp(f.LastPoll)
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}
	createdAtTime, err := pgxtypes.TimeFromTimestamp(f.CreatedAt)
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}

	// If this isn't the first poll, check rate limit
	if !lastPollTime.Equal(createdAtTime) && lastPollTime.Add(pollRate).After(now()) {
		return "", errors.Join(ErrPollingFlow, ErrRateLimitFlow)
	}

	if f.SessionIdentifier.Valid {
		session, err := qtx.GetSessionByIdentifier(ctx, f.SessionIdentifier)
		if err != nil {
			return "", errors.Join(ErrPollingFlow, err)
		}
		num, err := qtx.DeleteDeviceCodeFlowByIdentifier(ctx, f.Identifier)
		if err != nil {
			return "", errors.Join(ErrPollingFlow, err)
		}
		if num == 0 {
			return "", errors.Join(ErrPollingFlow, sql.ErrNoRows)
		}

		err = tx.Commit(ctx)
		if err != nil {
			return "", errors.Join(ErrPollingFlow, err)
		}

		sessionID, err := pgxtypes.StringFromUUID(session.Identifier)
		if err != nil {
			return "", errors.Join(ErrPollingFlow, err)
		}
		return sessionID, nil
	}

	num, err := qtx.UpdateDeviceCodeFlowLastPollByPoll(ctx, poll)
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}
	if num == 0 {
		return "", errors.Join(ErrPollingFlow, sql.ErrNoRows)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}

	return "", errors.Join(ErrPollingFlow, ErrFlowNotCompleted)
}

// CompleteFlow marks a device flow as completed by setting its session identifier
// Called from API handler - inputs should be pre-validated pgx types
// Defensive check: validates identifier.Valid and sessionIdentifier.Valid (returns error → 500 if invalid)
func (c *Device) CompleteFlow(ctx context.Context, identifier pgtype.UUID, sessionIdentifier pgtype.UUID) error {
	// Defensive validation - should never fail if API handler validated properly
	if !identifier.Valid {
		c.logger.Error().Msg("CompleteFlow called with invalid identifier - API handler validation failed")
		return errors.Join(ErrCompletingFlow, errors.New("invalid device identifier"))
	}
	// Note: sessionIdentifier can be invalid (Valid: false) if no session is set

	identifierStr, _ := pgxtypes.StringFromUUID(identifier)
	c.logger.Debug().Str("identifier", identifierStr).Msg("completing flow")

	num, err := c.db.Queries.UpdateDeviceCodeFlowSessionIdentifierByIdentifier(ctx, generated.UpdateDeviceCodeFlowSessionIdentifierByIdentifierParams{
		SessionIdentifier: sessionIdentifier,
		Identifier:        identifier,
	})
	if err != nil {
		return errors.Join(ErrCompletingFlow, err)
	}
	if num == 0 {
		return errors.Join(ErrCompletingFlow, sql.ErrNoRows)
	}
	return nil
}

func (c *Device) gc() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	ts, err := pgxtypes.TimestampFromTime(now().Add(-Expiry))
	if err != nil {
		return 0, err
	}
	return c.db.Queries.DeleteDeviceCodeFlowsBeforeCreatedAt(ctx, ts)
}

func (c *Device) doGC() {
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
