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
	"github.com/loopholelabs/auth/pkg/credential"
	"github.com/loopholelabs/auth/pkg/manager/configuration"
)

const (
	Timeout = time.Second * 30
)

var (
	ErrCreatingValidator  = errors.New("error creating validator")
	ErrDBIsRequired       = errors.New("db is required")
	ErrValidatingSession  = errors.New("error validating session")
	ErrRevokedSession     = errors.New("revoked session")
	ErrInvalidatedSession = errors.New("invalidated session")
)

type Options struct {
	Configuration configuration.Options
}

type InvalidatedSession struct {
	Identifier string `json:"identifier"`
	Generation uint32 `json:"generation"`
}

type Validator struct {
	logger types.Logger
	db     *db.DB

	configuration *configuration.Configuration

	sessionRevocationCache   *ttlcache.Cache[string, struct{}]
	sessionInvalidationCache *ttlcache.Cache[string, uint32]

	sessionRevocationHealthy   bool
	sessionInvalidationHealthy bool
	mu                         sync.RWMutex

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
	sessionInvalidationCache := ttlcache.New[string, uint32](ttlcache.WithTTL[string, uint32](c.SessionExpiry()))

	ctx, cancel := context.WithCancel(context.Background())
	v := &Validator{
		logger:                   logger,
		db:                       db,
		configuration:            c,
		sessionRevocationCache:   sessionRevocationCache,
		sessionInvalidationCache: sessionInvalidationCache,
		ctx:                      ctx,
		cancel:                   cancel,
	}

	v.sessionRevocationsRefresh()
	v.sessionInvalidationsRefresh()

	v.wg.Add(1)
	go v.doRefresh()

	return v, nil
}

func (v *Validator) IsSessionValid(token string) (credential.Session, bool, error) {
	_, publicKey := v.Configuration().SigningKey()
	_, previousPublicKey := v.Configuration().PreviousSigningKey()
	session, replace, err := credential.ParseSession(token, publicKey, previousPublicKey)
	if err != nil {
		return credential.Session{}, replace, errors.Join(ErrValidatingSession, err)
	}
	if v.IsSessionRevoked(session.Identifier) {
		return credential.Session{}, replace, errors.Join(ErrValidatingSession, ErrRevokedSession)
	}
	if v.IsSessionInvalidated(session.Identifier, session.Generation) {
		return credential.Session{}, replace, errors.Join(ErrValidatingSession, ErrInvalidatedSession)
	}

	return session, replace, nil
}

func (v *Validator) IsSessionRevoked(identifier string) bool {
	return v.sessionRevocationCache.Get(identifier, ttlcache.WithDisableTouchOnHit[string, struct{}]()) != nil
}

func (v *Validator) IsSessionInvalidated(identifier string, generation uint32) bool {
	item := v.sessionInvalidationCache.Get(identifier, ttlcache.WithDisableTouchOnHit[string, uint32]())
	if item == nil {
		return false
	}
	return item.Value() >= generation
}

func (v *Validator) SessionRevocationList() []string {
	return v.sessionRevocationCache.Keys()
}

func (v *Validator) SessionInvalidationList() []InvalidatedSession {
	items := v.sessionInvalidationCache.Items()
	sessions := make([]InvalidatedSession, 0, len(items))
	for _, item := range items {
		sessions = append(sessions, InvalidatedSession{
			Identifier: item.Key(),
			Generation: item.Value(),
		})
	}
	return sessions
}

func (v *Validator) Configuration() *configuration.Configuration {
	return v.configuration
}

func (v *Validator) IsHealthy() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.sessionRevocationHealthy && v.sessionInvalidationHealthy
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
		v.mu.Lock()
		v.sessionRevocationHealthy = false
		v.mu.Unlock()
	} else {
		for _, sessionRevocation := range sessionRevocations {
			if sessionRevocation.ExpiresAt.After(time.Now()) {
				v.sessionRevocationCache.Set(sessionRevocation.SessionIdentifier, struct{}{}, time.Until(sessionRevocation.ExpiresAt))
				refreshed++
			}
		}
		v.logger.Info().Msgf("refresh %d session revocations", refreshed)
		v.mu.Lock()
		v.sessionRevocationHealthy = true
		v.mu.Unlock()
	}
}

func (v *Validator) sessionInvalidationsRefresh() {
	v.sessionInvalidationCache.DeleteExpired()
	ctx, cancel := context.WithTimeout(v.ctx, Timeout)
	defer cancel()
	refreshed := 0
	sessionInvalidations, err := v.db.Queries.GetAllSessionInvalidations(ctx)
	if err != nil {
		v.logger.Error().Err(err).Msg("failed to update session invalidations")
		v.mu.Lock()
		v.sessionInvalidationHealthy = false
		v.mu.Unlock()
	} else {
		for _, sessionInvalidation := range sessionInvalidations {
			if sessionInvalidation.ExpiresAt.After(time.Now()) {
				v.sessionInvalidationCache.Set(sessionInvalidation.SessionIdentifier, sessionInvalidation.Generation, time.Until(sessionInvalidation.ExpiresAt))
				refreshed++
			}
		}
		v.logger.Info().Msgf("refresh %d session invalidations", refreshed)
		v.mu.Lock()
		v.sessionInvalidationHealthy = true
		v.mu.Unlock()
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
			v.sessionInvalidationsRefresh()
		}
	}
}
