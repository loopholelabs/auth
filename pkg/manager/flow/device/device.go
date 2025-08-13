//SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
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
	params := generated.CreateDeviceCodeFlowParams{
		Identifier: uuid.New().String(),
		Code:       utils.RandomBase32String(8),
		Poll:       uuid.New().String(),
	}

	c.logger.Debug().Msg("creating flow")
	err := c.db.Queries.CreateDeviceCodeFlow(ctx, params)
	if err != nil {
		return "", "", errors.Join(ErrCreatingFlow, err)
	}

	return params.Code, params.Poll, nil
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
	return f.Identifier, nil
}

func (c *Device) PollFlow(ctx context.Context, poll string, pollRate time.Duration) (string, error) {
	c.logger.Debug().Str("poll", poll).Msg("polling flow")
	tx, err := c.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			c.logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()

	qtx := c.db.Queries.WithTx(tx)

	f, err := qtx.GetDeviceCodeFlowByPoll(ctx, poll)
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}

	if f.LastPoll.Add(pollRate).Before(now()) {
		return "", errors.Join(ErrPollingFlow, ErrRateLimitFlow)
	}

	if f.SessionIdentifier.String != "" {
		session, err := qtx.GetSessionByIdentifier(ctx, f.SessionIdentifier.String)
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

		err = tx.Commit()
		if err != nil {
			return "", errors.Join(ErrPollingFlow, err)
		}

		return session.Identifier, nil
	}

	num, err := qtx.UpdateDeviceCodeFlowLastPollByPoll(ctx, poll)
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}
	if num == 0 {
		return "", errors.Join(ErrPollingFlow, sql.ErrNoRows)
	}

	err = tx.Commit()
	if err != nil {
		return "", errors.Join(ErrPollingFlow, err)
	}

	return "", errors.Join(ErrPollingFlow, ErrFlowNotCompleted)
}

func (c *Device) CompleteFlow(ctx context.Context, identifier string, sessionIdentifier string) error {
	c.logger.Debug().Str("identifier", identifier).Msg("completing flow")
	num, err := c.db.Queries.UpdateDeviceCodeFlowSessionIdentifierByIdentifier(ctx, generated.UpdateDeviceCodeFlowSessionIdentifierByIdentifierParams{
		SessionIdentifier: sql.NullString{
			String: sessionIdentifier,
			Valid:  sessionIdentifier != "",
		},
		Identifier: identifier,
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
	return c.db.Queries.DeleteDeviceCodeFlowsBeforeCreatedAt(ctx, now().Add(-Expiry))
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
