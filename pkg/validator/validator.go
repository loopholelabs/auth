//SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
)

const (
	Timeout = time.Second * 30
)

var (
	ErrCreatingValidator = errors.New("error creating validator")
	ErrDBIsRequired      = errors.New("db is required")
)

type Options struct {
	Configuration configuration.Options
}

type Validator struct {
	logger types.Logger
	db     *db.DB

	configuration *configuration.Configuration

	sessionRevocationCache   *ttlcache.Cache[string, struct{}]
	sessionRevalidationCache *ttlcache.Cache[string, uint32]

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func New(options Options, db *db.DB, logger types.Logger) (*Validator, error) {
	logger = logger.SubLogger("VALIDATOR")
	if db == nil {
		return nil, errors.Join(ErrCreatingValidator, ErrDBIsRequired)
	}

	c, err := configuration.New(options.Configuration, db, logger)
	if err != nil {
		return nil, errors.Join(ErrCreatingValidator, err)
	}

	sessionRevocationCache := ttlcache.New[string, struct{}](ttlcache.WithTTL[string, struct{}](c.SessionExpiry()))
	sessionRevalidationCache := ttlcache.New[string, uint32](ttlcache.WithTTL[string, uint32](c.SessionExpiry()))

	ctx, cancel := context.WithCancel(context.Background())
	v := &Validator{
		logger:                   logger,
		db:                       db,
		configuration:            c,
		sessionRevocationCache:   sessionRevocationCache,
		sessionRevalidationCache: sessionRevalidationCache,
		ctx:                      ctx,
		cancel:                   cancel,
	}

	v.sessionRevocationsRefresh()
	v.sessionRevalidationsRefresh()

	v.wg.Add(1)
	go v.doRefresh()

	return v, nil
}

func (v *Validator) IsSessionRevoked(identifier string) bool {
	return v.sessionRevocationCache.Get(identifier, ttlcache.WithDisableTouchOnHit[string, struct{}]()) != nil
}

func (v *Validator) IsSessionRevalidated(identifier string, generation uint32) bool {
	item := v.sessionRevalidationCache.Get(identifier, ttlcache.WithDisableTouchOnHit[string, uint32]())
	if item == nil {
		return false
	}
	return item.Value() >= generation
}

func (v *Validator) Configuration() *configuration.Configuration {
	return v.configuration
}

func (v *Validator) Close() error {
	v.cancel()
	v.wg.Wait()

	err := v.configuration.Close()
	if err != nil {
		return err
	}

	return nil
}

func (v *Validator) sessionRevocationsRefresh() {
	v.sessionRevocationCache.DeleteExpired()
	ctx, cancel := context.WithTimeout(v.ctx, Timeout)
	defer cancel()
	refreshed := 0
	sessionRevocations, err := v.db.Queries.GetAllSessionRevocations(ctx)
	if err != nil {
		v.logger.Error().Err(err).Msg("failed to update session revocations")
	} else {
		for _, sessionRevocation := range sessionRevocations {
			if sessionRevocation.ExpiresAt.After(time.Now()) {
				v.sessionRevocationCache.Set(sessionRevocation.SessionIdentifier, struct{}{}, time.Until(sessionRevocation.ExpiresAt))
				refreshed++
			}
		}
		v.logger.Info().Msgf("refresh %d session revocations", refreshed)
	}
}

func (v *Validator) sessionRevalidationsRefresh() {
	v.sessionRevalidationCache.DeleteExpired()
	ctx, cancel := context.WithTimeout(v.ctx, Timeout)
	defer cancel()
	refreshed := 0
	sessionRevalidations, err := v.db.Queries.GetAllSessionRevalidations(ctx)
	if err != nil {
		v.logger.Error().Err(err).Msg("failed to update session revalidations")
	} else {
		for _, sessionRevalidation := range sessionRevalidations {
			if sessionRevalidation.ExpiresAt.After(time.Now()) {
				v.sessionRevalidationCache.Set(sessionRevalidation.SessionIdentifier, sessionRevalidation.Generation, time.Until(sessionRevalidation.ExpiresAt))
				refreshed++
			}
		}
		v.logger.Info().Msgf("refresh %d session revalidations", refreshed)
	}
}

func (v *Validator) doRefresh() {
	defer v.wg.Done()
	for {
		select {
		case <-v.ctx.Done():
			v.logger.Info().Msg("refresh stopped")
			return
		case <-time.After(v.Configuration().PollInterval()):
			v.sessionRevocationsRefresh()
			v.sessionRevalidationsRefresh()
		}
	}
}
