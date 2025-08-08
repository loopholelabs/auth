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
	"github.com/loopholelabs/auth/internal/db/generated"
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

func (v *Validator) sessionRevocationsRefresh() ([]generated.SessionRevocation, error) {
	ctx, cancel := context.WithTimeout(v.ctx, Timeout)
	defer cancel()
	return v.db.Queries.GetAllSessionRevocations(ctx)
}

func (v *Validator) sessionRevalidationsRefresh() ([]generated.SessionRevalidation, error) {
	ctx, cancel := context.WithTimeout(v.ctx, Timeout)
	defer cancel()
	return v.db.Queries.GetAllSessionRevalidations(ctx)
}

func (v *Validator) doRefresh() {
	defer v.wg.Done()
	for {
		select {
		case <-v.ctx.Done():
			v.logger.Info().Msg("refresh stopped")
			return
		case <-time.After(v.Configuration().PollInterval()):
			v.sessionRevocationCache.DeleteExpired()
			v.sessionRevalidationCache.DeleteExpired()

			sessionRevocations, err := v.sessionRevocationsRefresh()
			if err != nil {
				v.logger.Error().Err(err).Msg("failed to update session revocations")
			} else {
				for _, sessionRevocation := range sessionRevocations {
					v.sessionRevocationCache.Set(sessionRevocation.SessionIdentifier, struct{}{}, time.Until(sessionRevocation.ExpiresAt))
				}
				v.logger.Info().Msgf("refresh %d session revocations", len(sessionRevocations))
			}

			sessionRevalidations, err := v.sessionRevalidationsRefresh()
			if err != nil {
				v.logger.Error().Err(err).Msg("failed to update session revalidations")
			} else {
				for _, sessionRevalidation := range sessionRevalidations {
					v.sessionRevalidationCache.Set(sessionRevalidation.SessionIdentifier, sessionRevalidation.Generation, time.Until(sessionRevalidation.ExpiresAt))
				}
				v.logger.Info().Msgf("refresh %d session revalidations", len(sessionRevalidations))
			}
		}
	}
}
