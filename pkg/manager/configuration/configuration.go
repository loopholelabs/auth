//SPDX-License-Identifier: Apache-2.0

package configuration

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/utils"
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
	ErrSettingDefaultSigningKey   = errors.New("error setting default signing key")
	ErrRotatingSigningKey         = errors.New("error rotating signing key")
)

type Key string

const (
	PollIntervalKey    Key = "poll_interval"
	SessionExpiryKey   Key = "session_expiry"
	SigningKey         Key = "signing_key"
	PreviousSigningKey Key = "previous_signing_key"
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

	pollInterval             time.Duration
	sessionExpiry            time.Duration
	signingKey               ed25519.PrivateKey
	previousSigningKey       ed25519.PrivateKey
	publicKey                crypto.PublicKey
	previousPublicKey        crypto.PublicKey
	encodedPublicKey         []byte
	encodedPreviousPublicKey []byte

	healthy bool

	mu sync.RWMutex

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

	g.update()

	g.wg.Add(1)
	go g.doUpdate()

	return g, nil
}

func (c *Configuration) IsHealthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
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

func (c *Configuration) SigningKey() (ed25519.PrivateKey, crypto.PublicKey) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.signingKey, c.publicKey
}

func (c *Configuration) PreviousSigningKey() (ed25519.PrivateKey, crypto.PublicKey) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.previousSigningKey, c.previousPublicKey
}

func (c *Configuration) EncodedPublicKey() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.encodedPublicKey
}

func (c *Configuration) EncodedPreviousPublicKey() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.encodedPreviousPublicKey
}

func (c *Configuration) RotateSigningKey(ctx context.Context) error {
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Join(ErrRotatingSigningKey, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	tx, err := c.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return errors.Join(ErrRotatingSigningKey, err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rollbackCancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			c.logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()
	qtx := c.db.Queries.WithTx(tx)
	cfg, err := qtx.GetConfigurationByKey(ctx, SigningKey.String())
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.Join(ErrRotatingSigningKey, err)
		}
		err = qtx.SetConfiguration(ctx, generated.SetConfigurationParams{
			ConfigurationKey:   SigningKey.String(),
			ConfigurationValue: base64.StdEncoding.EncodeToString(utils.EncodeED25519PrivateKey(signingKey)),
		})
		if err != nil {
			return errors.Join(ErrRotatingSigningKey, err)
		}

		err = tx.Commit(ctx)
		if err != nil {
			return errors.Join(ErrRotatingSigningKey, err)
		}

		c.signingKey = signingKey
		c.publicKey = signingKey.Public()
		c.encodedPublicKey = utils.EncodePublicKey(c.publicKey)
		c.previousSigningKey = nil
		c.previousPublicKey = nil
		c.encodedPreviousPublicKey = nil
		return nil
	}

	pemPreviousSigningKey, err := base64.StdEncoding.DecodeString(cfg.ConfigurationValue)
	if err != nil {
		return errors.Join(ErrRotatingSigningKey, err)
	}

	previousSigningKey, err := utils.DecodeED25519PrivateKey(pemPreviousSigningKey)
	if err != nil {
		return errors.Join(ErrRotatingSigningKey, err)
	}

	err = qtx.SetConfiguration(ctx, generated.SetConfigurationParams{
		ConfigurationKey:   PreviousSigningKey.String(),
		ConfigurationValue: cfg.ConfigurationValue,
	})
	if err != nil {
		return errors.Join(ErrRotatingSigningKey, err)
	}

	err = qtx.SetConfiguration(ctx, generated.SetConfigurationParams{
		ConfigurationKey:   SigningKey.String(),
		ConfigurationValue: base64.StdEncoding.EncodeToString(utils.EncodeED25519PrivateKey(signingKey)),
	})
	if err != nil {
		return errors.Join(ErrRotatingSigningKey, err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return errors.Join(ErrRotatingSigningKey, err)
	}

	c.signingKey = signingKey
	c.publicKey = previousSigningKey.Public()
	c.encodedPublicKey = utils.EncodePublicKey(c.publicKey)
	c.previousSigningKey = previousSigningKey
	c.previousPublicKey = previousSigningKey.Public()
	c.encodedPreviousPublicKey = utils.EncodePublicKey(c.previousPublicKey)

	return nil
}

func (c *Configuration) Close() error {
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *Configuration) setDefault(key Key, value string) (string, error) {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	tx, err := c.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", errors.Join(ErrSettingConfiguration, err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rollbackCancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
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
	err = tx.Commit(ctx)
	if err != nil {
		return "", errors.Join(ErrSettingConfiguration, err)
	}
	return cfg.ConfigurationValue, nil
}

func (c *Configuration) setDefaultSigningKey() error {
	_, defaultSigningKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Join(ErrSettingDefaultSigningKey, err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	tx, err := c.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return errors.Join(ErrSettingDefaultSigningKey, err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rollbackCancel()
		err := tx.Rollback(rollbackCtx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			c.logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()
	qtx := c.db.Queries.WithTx(tx)
	cfg, err := qtx.GetConfigurationByKey(ctx, SigningKey.String())
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.Join(ErrSettingDefaultSigningKey, err)
		}
		err = qtx.SetConfiguration(ctx, generated.SetConfigurationParams{
			ConfigurationKey:   SigningKey.String(),
			ConfigurationValue: base64.StdEncoding.EncodeToString(utils.EncodeED25519PrivateKey(defaultSigningKey)),
		})
		if err != nil {
			return errors.Join(ErrSettingDefaultSigningKey, err)
		}

		err = tx.Commit(ctx)
		if err != nil {
			return errors.Join(ErrSettingDefaultSigningKey, err)
		}

		c.signingKey = defaultSigningKey
		c.publicKey = defaultSigningKey.Public()
		c.encodedPublicKey = utils.EncodePublicKey(c.publicKey)
		c.previousSigningKey = nil
		c.previousPublicKey = nil
		c.encodedPreviousPublicKey = nil
		return nil
	}

	pemSigningKey, err := base64.StdEncoding.DecodeString(cfg.ConfigurationValue)
	if err != nil {
		return errors.Join(ErrSettingDefaultSigningKey, err)
	}

	signingKey, err := utils.DecodeED25519PrivateKey(pemSigningKey)
	if err != nil {
		return errors.Join(ErrSettingDefaultSigningKey, err)
	}

	cfg, err = qtx.GetConfigurationByKey(ctx, PreviousSigningKey.String())
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.Join(ErrSettingDefaultSigningKey, err)
		}

		c.signingKey = signingKey
		c.publicKey = signingKey.Public()
		c.encodedPublicKey = utils.EncodePublicKey(c.publicKey)
		c.previousSigningKey = nil
		c.previousPublicKey = nil
		c.encodedPreviousPublicKey = nil

		err = tx.Commit(ctx)
		if err != nil {
			return errors.Join(ErrSettingDefaultSigningKey, err)
		}

		return nil
	}

	pemPreviousSigningKey, err := base64.StdEncoding.DecodeString(cfg.ConfigurationValue)
	if err != nil {
		return errors.Join(ErrSettingDefaultSigningKey, err)
	}

	previousSigningKey, err := utils.DecodeED25519PrivateKey(pemPreviousSigningKey)
	if err != nil {
		return errors.Join(ErrSettingDefaultSigningKey, err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return errors.Join(ErrSettingDefaultSigningKey, err)
	}

	c.signingKey = signingKey
	c.publicKey = previousSigningKey.Public()
	c.encodedPublicKey = utils.EncodePublicKey(c.publicKey)
	c.previousSigningKey = previousSigningKey
	c.previousPublicKey = previousSigningKey.Public()
	c.encodedPreviousPublicKey = utils.EncodePublicKey(c.previousPublicKey)

	return nil
}

func (c *Configuration) init(options Options) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.setDefaultSigningKey()
	if err != nil {
		return errors.Join(ErrInitializingConfigurations, err)
	}

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

func (c *Configuration) update() {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	healthy := true
	c.mu.Lock()
	defer c.mu.Unlock()
	configurations, err := c.db.Queries.GetAllConfigurations(ctx)
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to update configurations")
		healthy = false
	} else {
		for _, configuration := range configurations {
			switch Key(configuration.ConfigurationKey) {
			case PollIntervalKey:
				var pollInterval time.Duration
				pollInterval, err = time.ParseDuration(configuration.ConfigurationValue)
				if err != nil {
					c.logger.Error().Err(err).Msg("failed to parse poll interval configuration")
					healthy = false
					continue
				}
				c.pollInterval = pollInterval
			case SessionExpiryKey:
				var sessionExpiry time.Duration
				sessionExpiry, err = time.ParseDuration(configuration.ConfigurationValue)
				if err != nil {
					c.logger.Error().Err(err).Msg("failed to parse session expiry configuration")
					healthy = false
					continue
				}
				c.sessionExpiry = sessionExpiry
			case SigningKey:
				pemSigningKey, err := base64.StdEncoding.DecodeString(configuration.ConfigurationValue)
				if err != nil {
					c.logger.Error().Err(err).Msg("failed to decode base64 signing key")
					healthy = false
					continue
				}

				signingKey, err := utils.DecodeED25519PrivateKey(pemSigningKey)
				if err != nil {
					c.logger.Error().Err(err).Msg("failed to decode PEM signing key")
					healthy = false
					continue
				}

				c.signingKey = signingKey
				c.publicKey = signingKey.Public()
				c.encodedPublicKey = utils.EncodePublicKey(c.publicKey)
			case PreviousSigningKey:
				pemPreviousSigningKey, err := base64.StdEncoding.DecodeString(configuration.ConfigurationValue)
				if err != nil {
					c.logger.Error().Err(err).Msg("failed to decode base64 previous signing key")
					healthy = false
					continue
				}

				previousSigningKey, err := utils.DecodeED25519PrivateKey(pemPreviousSigningKey)
				if err != nil {
					c.logger.Error().Err(err).Msg("failed to decode PEM previous signing key")
					healthy = false
					continue
				}

				c.previousSigningKey = previousSigningKey
				c.previousPublicKey = previousSigningKey.Public()
				c.encodedPreviousPublicKey = utils.EncodePublicKey(c.previousPublicKey)
			default:
				c.logger.Info().Msgf("update skipped for unknown configuration key: %s", configuration.ConfigurationKey)
				healthy = false
			}
		}
	}
	c.healthy = healthy
}

func (c *Configuration) doUpdate() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			c.logger.Debug().Msg("update stopped")
			return
		case <-time.After(c.PollInterval()):
			c.update()
		}
	}
}
