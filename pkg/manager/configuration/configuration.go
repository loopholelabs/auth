//SPDX-License-Identifier: Apache-2.0

package configuration

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
)

const (
	Timeout = time.Second * 30
)

var (
	ErrInvalidOptions             = errors.New("invalid options")
	ErrDBIsRequired               = errors.New("db is required")
	ErrInitializingConfigurations = errors.New("error initializing configurations")
	ErrGettingConfiguration       = errors.New("error getting configuration")
	ErrSettingConfiguration       = errors.New("error setting configuration")
)

type Key string

const (
	PollIntervalKey  Key = "poll_interval"
	SessionExpiryKey Key = "session_expiry"
)

func (k Key) String() string {
	return string(k)
}

type Options struct {
	PollInterval  time.Duration
	SessionExpiry time.Duration
}

type Configuration struct {
	logger types.Logger
	db     *db.DB

	pollInterval  time.Duration
	sessionExpiry time.Duration
	mu            sync.RWMutex

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func New(options Options, db *db.DB, logger types.Logger) (*Configuration, error) {
	if options.PollInterval == 0 || options.SessionExpiry == 0 {
		return nil, ErrInvalidOptions
	}

	if db == nil {
		return nil, ErrDBIsRequired
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &Configuration{
		logger: logger.SubLogger("CONFIGURATION"),
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}

	err := g.init(options)
	if err != nil {
		return nil, err
	}

	g.wg.Add(1)
	go g.doUpdate()

	return g, nil
}

func (c *Configuration) PollInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pollInterval
}

func (c *Configuration) SessionExpiry() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionExpiry
}

func (c *Configuration) Close() error {
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *Configuration) setDefault(key Key, value string) (string, error) {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	tx, err := c.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", errors.Join(ErrSettingConfiguration, err)
	}
	defer func() {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			c.logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()
	qtx := c.db.Queries.WithTx(tx)
	cfg, err := qtx.GetConfigurationByKey(ctx, key.String())
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", errors.Join(ErrGettingConfiguration, err)
		}
		err = qtx.SetConfiguration(ctx, generated.SetConfigurationParams{
			ConfigurationKey:   key.String(),
			ConfigurationValue: value,
		})
		if err != nil {
			return "", errors.Join(ErrSettingConfiguration, err)
		}
		cfg, err = qtx.GetConfigurationByKey(ctx, key.String())
		if err != nil {
			return "", errors.Join(ErrGettingConfiguration, err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return "", errors.Join(ErrSettingConfiguration, err)
	}
	return cfg.ConfigurationValue, nil
}

func (c *Configuration) init(options Options) error {
	pollInterval, err := c.setDefault(PollIntervalKey, options.PollInterval.String())
	if err != nil {
		return errors.Join(ErrInitializingConfigurations, err)
	}
	c.pollInterval, err = time.ParseDuration(pollInterval)
	if err != nil {
		return errors.Join(ErrInitializingConfigurations, err)
	}

	sessionExpiry, err := c.setDefault(SessionExpiryKey, options.SessionExpiry.String())
	if err != nil {
		return errors.Join(ErrInitializingConfigurations, err)
	}
	c.sessionExpiry, err = time.ParseDuration(sessionExpiry)
	if err != nil {
		return errors.Join(ErrInitializingConfigurations, err)
	}

	return nil
}

func (c *Configuration) update() ([]generated.Configuration, error) {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	return c.db.Queries.GetAllConfigurations(ctx)
}

func (c *Configuration) doUpdate() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			c.logger.Info().Msg("update stopped")
			return
		case <-time.After(c.PollInterval()):
			configurations, err := c.update()
			if err != nil {
				c.logger.Error().Err(err).Msg("failed to update configurations")
			} else {
				c.mu.Lock()
				for _, configuration := range configurations {
					switch Key(configuration.ConfigurationKey) {
					case PollIntervalKey:
						var pollInterval time.Duration
						pollInterval, err = time.ParseDuration(configuration.ConfigurationValue)
						if err != nil {
							c.logger.Error().Err(err).Msg("failed to parse poll interval configuration")
							continue
						}
						c.pollInterval = pollInterval
					case SessionExpiryKey:
						var sessionExpiry time.Duration
						sessionExpiry, err = time.ParseDuration(configuration.ConfigurationValue)
						if err != nil {
							c.logger.Error().Err(err).Msg("failed to parse session expiry configuration")
							continue
						}
						c.sessionExpiry = sessionExpiry
					default:
						c.logger.Info().Msgf("update skipped for unknown configuration key: %s", configuration.ConfigurationKey)
					}
				}
				c.mu.Unlock()
			}
		}
	}
}
