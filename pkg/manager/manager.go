/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth"
	"github.com/loopholelabs/auth/internal/aes"
	"github.com/loopholelabs/auth/pkg/apikey"
	"github.com/loopholelabs/auth/pkg/claims"
	"github.com/loopholelabs/auth/pkg/kind"
	"github.com/loopholelabs/auth/pkg/provider"
	"github.com/loopholelabs/auth/pkg/servicekey"
	"github.com/loopholelabs/auth/pkg/session"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
	"sync"
	"time"
)

const (
	CookieKeyString           = "auth-session"
	AuthorizationHeaderString = "Authorization"
	BearerHeaderString        = "Bearer "
	KeyDelimiterString        = "."
)

var (
	CookieKey           = []byte(CookieKeyString)
	AuthorizationHeader = []byte(AuthorizationHeaderString)
	BearerHeader        = []byte(BearerHeaderString)
	KeyDelimiter        = []byte(KeyDelimiterString)
)

type Manager struct {
	logger  *zerolog.Logger
	storage storage.Storage
	domain  string
	tls     bool
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	secretKey    []byte
	oldSecretKey []byte
	secretKeyMu  sync.RWMutex

	registration   bool
	registrationMu sync.RWMutex

	sessions   map[string]struct{}
	sessionsMu sync.RWMutex

	servicekeySessions   map[string]*servicekey.Session
	servicekeySessionsMu sync.RWMutex

	apikeys   map[string]*apikey.APIKey
	apikeysMu sync.RWMutex
}

func New(domain string, tls bool, storage storage.Storage, logger *zerolog.Logger) *Manager {
	l := logger.With().Str("AUTH", "SESSION-MANAGER").Logger()
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		logger:             &l,
		storage:            storage,
		domain:             domain,
		tls:                tls,
		ctx:                ctx,
		cancel:             cancel,
		sessions:           make(map[string]struct{}),
		servicekeySessions: make(map[string]*servicekey.Session),
		apikeys:            make(map[string]*apikey.APIKey),
	}
}

func (m *Manager) Start() error {
	m.logger.Info().Msg("starting manager")

	m.secretKeyMu.Lock()
	secretKeyEvents, err := m.storage.SubscribeToSecretKey(m.ctx)
	if err != nil {
		m.secretKeyMu.Unlock()
		return fmt.Errorf("failed to subscribe to secret key events: %w", err)
	}
	m.wg.Add(1)
	go m.subscribeToSecretKeyEvents(secretKeyEvents)
	m.logger.Info().Msg("subscribed to secret key events")
	m.secretKey, err = m.storage.GetSecretKey(m.ctx)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			m.logger.Info().Msg("no secret key found, generating new one")
			m.secretKey = utils.RandomBytes(32)
			err = m.storage.SetSecretKey(m.ctx, m.secretKey)
			m.secretKeyMu.Unlock()
			if err != nil {
				return fmt.Errorf("failed to set secret key: %w", err)
			}
		} else {
			m.secretKeyMu.Unlock()
			return fmt.Errorf("failed to get secret key: %w", err)
		}
	} else {
		m.secretKeyMu.Unlock()
	}
	m.logger.Info().Msg("retrieved secret key")

	m.registrationMu.Lock()
	registrationEvents, err := m.storage.SubscribeToRegistration(m.ctx)
	if err != nil {
		m.registrationMu.Unlock()
		return fmt.Errorf("failed to subscribe to registration events: %w", err)
	}
	m.wg.Add(1)
	go m.subscribeToRegistrationEvents(registrationEvents)
	m.logger.Info().Msg("subscribed to registration events")
	m.registration, err = m.storage.GetRegistration(m.ctx)
	m.registrationMu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to get registration: %w", err)
	}
	m.logger.Info().Msg("retrieved registration")

	m.sessionsMu.Lock()
	sessionEvents, err := m.storage.SubscribeToSessionIDs(m.ctx)
	if err != nil {
		m.sessionsMu.Unlock()
		return fmt.Errorf("failed to subscribe to session events: %w", err)
	}
	m.wg.Add(1)
	go m.subscribeToSessionIDEvents(sessionEvents)
	m.logger.Info().Msg("subscribed to session ID events")
	sessions, err := m.storage.ListSessionIDs(m.ctx)
	if err != nil {
		m.sessionsMu.Unlock()
		return fmt.Errorf("failed to list session IDs: %w", err)
	}
	for _, sess := range sessions {
		m.sessions[sess] = struct{}{}
	}
	m.sessionsMu.Unlock()
	m.logger.Info().Msg("retrieved session IDs")

	m.servicekeySessionsMu.Lock()
	servicekeySessionEvents, err := m.storage.SubscribeToServiceKeySessions(m.ctx)
	if err != nil {
		m.servicekeySessionsMu.Unlock()
		return fmt.Errorf("failed to subscribe to service key session events: %w", err)
	}
	m.wg.Add(1)
	go m.subscribeToServiceKeySessionEvents(servicekeySessionEvents)
	m.logger.Info().Msg("subscribed to service key session events")
	servicekeySessionIDs, err := m.storage.ListServiceKeySessions(m.ctx)
	if err != nil {
		m.servicekeySessionsMu.Unlock()
		return fmt.Errorf("failed to list service key session IDs: %w", err)
	}
	for _, sess := range servicekeySessionIDs {
		m.servicekeySessions[sess.ID] = sess
	}
	m.servicekeySessionsMu.Unlock()
	m.logger.Info().Msg("retrieved service key sessions")

	m.apikeysMu.Lock()
	apikeyEvents, err := m.storage.SubscribeToAPIKeys(m.ctx)
	if err != nil {
		m.apikeysMu.Unlock()
		return fmt.Errorf("failed to subscribe to api key events: %w", err)
	}
	m.wg.Add(1)
	go m.subscribeToAPIKeyEvents(apikeyEvents)
	m.logger.Info().Msg("subscribed to api key events")
	apikeys, err := m.storage.ListAPIKeys(m.ctx)
	if err != nil {
		m.apikeysMu.Unlock()
		return fmt.Errorf("failed to list api keys: %w", err)
	}
	for _, key := range apikeys {
		m.apikeys[key.ID] = key
	}
	m.apikeysMu.Unlock()
	m.logger.Info().Msg("retrieved api keys")

	return nil
}

func (m *Manager) Stop() error {
	m.logger.Info().Msg("stopping manager")
	m.cancel()
	m.wg.Wait()
	return nil
}

func (m *Manager) GenerateCookie(session string, expiry time.Time) *fiber.Cookie {
	m.logger.Debug().Msgf("generating cookie with expiry %s", expiry)
	return &fiber.Cookie{
		Name:     CookieKeyString,
		Value:    session,
		Domain:   m.domain,
		Expires:  expiry,
		Secure:   m.tls,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	}
}

func (m *Manager) CreateSession(ctx *fiber.Ctx, kind kind.Kind, provider provider.Key, userID string, organization string) (*fiber.Cookie, error) {
	m.logger.Debug().Msgf("creating session for user %s (org '%s')", userID, organization)
	exists, err := m.storage.UserExists(ctx.Context(), userID)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to check if user exists")
		return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if user exists")
	}

	if !exists {
		if organization != "" {
			return nil, ctx.Status(fiber.StatusNotFound).SendString("user does not exist")
		}

		m.logger.Debug().Msgf("user %s does not exist", userID)
		m.registrationMu.RLock()
		registration := m.registration
		m.registrationMu.RUnlock()

		if !registration {
			return nil, ctx.Status(fiber.StatusNotFound).SendString("user does not exist")
		}

		m.logger.Debug().Msgf("creating user %s", userID)

		c := &claims.Claims{
			UserID: userID,
		}

		err = m.storage.NewUser(ctx.Context(), c)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to create user")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to create user")
		}
	}

	if organization != "" {
		m.logger.Debug().Msgf("checking if user %s is member of organization %s", userID, organization)
		exists, err = m.storage.UserOrganizationExists(ctx.Context(), userID, organization)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to check if organization exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if organization exists")
		}

		if !exists {
			return nil, ctx.Status(fiber.StatusForbidden).SendString("invalid organization")
		}
	}

	sess := session.New(kind, provider, userID, organization)
	data, err := json.Marshal(sess)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to marshal session")
		return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to marshal session")
	}

	m.secretKeyMu.RLock()
	secretKey := m.secretKey
	m.secretKeyMu.RUnlock()

	encrypted, err := aes.Encrypt(secretKey, CookieKey, data)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to encrypt session")
		return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to encrypt session")
	}

	err = m.storage.SetSession(ctx.Context(), sess)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to set session")
		return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to set session")
	}

	m.logger.Debug().Msgf("created session %s for user %s (org '%s') with expiry %s", sess.ID, sess.UserID, sess.Organization, sess.Expiry)

	return m.GenerateCookie(encrypted, sess.Expiry), nil
}

func (m *Manager) GetSession(ctx *fiber.Ctx, cookie string) (*session.Session, error) {
	m.secretKeyMu.RLock()
	secretKey := m.secretKey
	oldSecretKey := m.oldSecretKey
	m.secretKeyMu.RUnlock()

	oldSecretKeyUsed := false
	decrypted, err := aes.Decrypt(secretKey, CookieKey, cookie)
	if err != nil {
		if errors.Is(err, aes.ErrInvalidContent) {
			if oldSecretKey != nil {
				decrypted, err = aes.Decrypt(oldSecretKey, CookieKey, cookie)
				if err != nil {
					if errors.Is(err, aes.ErrInvalidContent) {
						return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid session cookie")
					}
					m.logger.Error().Err(err).Msg("failed to decrypt session with old secret key")
					return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to decrypt session")
				}
				oldSecretKeyUsed = true
			} else {
				return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid session cookie")
			}
		} else {
			m.logger.Error().Err(err).Msg("failed to decrypt session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to decrypt session")
		}
	}

	sess := new(session.Session)
	err = json.Unmarshal(decrypted, sess)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to unmarshal session")
		return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to unmarshal session")
	}

	if sess.Expired() {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("session expired")
	}

	m.sessionsMu.RLock()
	_, exists := m.sessions[sess.ID]
	m.sessionsMu.RUnlock()
	if !exists {
		exists, err = m.storage.SessionIDExists(ctx.Context(), sess.ID)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to check if session exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if session exists")
		}
		if !exists {
			return nil, ctx.Status(fiber.StatusUnauthorized).SendString("session does not exist")
		}
	}

	if oldSecretKeyUsed || sess.CloseToExpiry() {
		sess.Refresh()
		data, err := json.Marshal(sess)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to marshal refreshed session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to marshal session")
		}

		encrypted, err := aes.Encrypt(secretKey, CookieKey, data)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to encrypt refreshed session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to encrypt session")
		}

		err = m.storage.SetSession(ctx.Context(), sess)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to set refreshed session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to set session")
		}

		ctx.Cookie(m.GenerateCookie(encrypted, sess.Expiry))
	}

	return sess, nil
}

func (m *Manager) GetAPIKey(ctx *fiber.Ctx, keyID string, keySecret []byte) (*apikey.APIKey, error) {
	m.apikeysMu.RLock()
	key, ok := m.apikeys[keyID]
	m.apikeysMu.RUnlock()
	if !ok {
		var err error
		key, err = m.storage.GetAPIKey(ctx.Context(), keyID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ctx.Status(fiber.StatusUnauthorized).SendString("api key does not exist")
			}
			m.logger.Error().Err(err).Msg("failed to check if api key exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if api key exists")
		}
	}

	if bcrypt.CompareHashAndPassword(keySecret, key.Hash) != nil {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid api key")
	}

	return key, nil
}

func (m *Manager) GetServiceKey(ctx *fiber.Ctx, keyID string, keySecret []byte) (*servicekey.ServiceKey, error) {
	key, err := m.storage.GetServiceKey(ctx.Context(), keyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ctx.Status(fiber.StatusUnauthorized).SendString("service key does not exist")
		}
		m.logger.Error().Err(err).Msg("failed to check if service key exists")
		return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if service key exists")
	}

	if bcrypt.CompareHashAndPassword(keySecret, key.Hash) != nil {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid service key")
	}

	return key, nil
}

func (m *Manager) CreateServiceKeySession(ctx *fiber.Ctx, keyID string, keySecret []byte) (*servicekey.Session, []byte, error) {
	serviceKey, err := m.GetServiceKey(ctx, keyID, keySecret)
	if err != nil {
		return nil, nil, err
	}

	if !serviceKey.Expires.IsZero() && time.Now().After(serviceKey.Expires) {
		return nil, nil, ctx.Status(fiber.StatusUnauthorized).SendString("service key expired")
	}

	if serviceKey.MaxUses != 0 && serviceKey.NumUsed >= serviceKey.MaxUses {
		return nil, nil, ctx.Status(fiber.StatusUnauthorized).SendString("service key has reached its maximum uses")
	}

	err = m.storage.IncrementServiceKeyNumUsed(ctx.Context(), serviceKey.ID)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to increment service key num used")
		return nil, nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to increment service key num used")
	}

	sess, secret, err := servicekey.NewSession(serviceKey)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to create service key session")
		return nil, nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to create service key session")
	}

	err = m.storage.SetServiceKeySession(ctx.Context(), sess)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to set service key session")
		return nil, nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to set service key session")
	}

	m.logger.Debug().Msgf("created service key session %s for user %s (org '%s')", sess.ID, sess.UserID, sess.Organization)

	return sess, secret, nil
}

func (m *Manager) GetServiceKeySession(ctx *fiber.Ctx, sessionID string, sessionSecret []byte) (*servicekey.Session, error) {
	m.servicekeySessionsMu.RLock()
	sess, ok := m.servicekeySessions[sessionID]
	m.servicekeySessionsMu.RUnlock()
	if !ok {
		var err error
		sess, err = m.storage.GetServiceKeySession(ctx.Context(), sessionID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ctx.Status(fiber.StatusUnauthorized).SendString("service key session does not exist")
			}
			m.logger.Error().Err(err).Msg("failed to check if service key session exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if service key session exists")
		}
	}

	if bcrypt.CompareHashAndPassword(sessionSecret, sess.Hash) != nil {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid service key session")
	}

	return sess, nil
}

func (m *Manager) Validate(ctx *fiber.Ctx) error {
	cookie := ctx.Cookies(CookieKeyString)
	if cookie != "" {
		sess, err := m.GetSession(ctx, cookie)
		if sess == nil {
			return err
		}

		ctx.Locals(auth.KindContextKey, auth.KindSession)
		ctx.Locals(auth.SessionContextKey, sess)
		ctx.Locals(auth.UserContextKey, sess.UserID)
		ctx.Locals(auth.OrganizationContextKey, sess.Organization)
		return ctx.Next()
	}

	authHeader := ctx.Request().Header.PeekBytes(AuthorizationHeader)
	if len(authHeader) > len(BearerHeader) {
		if !bytes.Equal(authHeader[:len(BearerHeader)], BearerHeader) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid authorization header")
		}
		authHeader = authHeader[len(BearerHeader):]
		keySplit := bytes.Split(authHeader, KeyDelimiter)
		if len(keySplit) != 2 {
			return ctx.Status(fiber.StatusUnauthorized).SendString("invalid authorization header")
		}

		keyID := string(keySplit[0])
		keySecret := keySplit[1]

		if bytes.HasPrefix(authHeader, auth.APIKeyPrefix) {
			key, err := m.GetAPIKey(ctx, keyID, keySecret)
			if key == nil {
				return err
			}

			ctx.Locals(auth.KindContextKey, auth.KindAPIKey)
			ctx.Locals(auth.APIKeyContextKey, key)
			ctx.Locals(auth.UserContextKey, key.UserID)
			ctx.Locals(auth.OrganizationContextKey, key.Organization)
			return ctx.Next()
		}

		if bytes.HasPrefix(authHeader, auth.ServiceKeySessionPrefix) {
			key, err := m.GetServiceKeySession(ctx, keyID, keySecret)
			if key == nil {
				return err
			}

			ctx.Locals(auth.KindContextKey, auth.KindServiceKey)
			ctx.Locals(auth.ServiceKeySessionContextKey, key)
			ctx.Locals(auth.UserContextKey, key.UserID)
			ctx.Locals(auth.OrganizationContextKey, key.Organization)
			return ctx.Next()
		}
	}

	return ctx.Status(fiber.StatusUnauthorized).SendString("no valid session cookie or authorization header")
}

func (m *Manager) LogoutSession(ctx *fiber.Ctx) error {
	cookie := ctx.Cookies(CookieKeyString)
	if cookie != "" {
		err := m.storage.DeleteSession(ctx.Context(), cookie)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to delete session")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to delete session")
		}
	}

	ctx.ClearCookie(CookieKeyString)
	return nil
}

func (m *Manager) LogoutServiceKeySession(ctx *fiber.Ctx) error {
	authHeader := ctx.Request().Header.PeekBytes(AuthorizationHeader)
	if len(authHeader) > len(BearerHeader) {
		if !bytes.Equal(authHeader[:len(BearerHeader)], BearerHeader) {
			return nil
		}

		authHeader = authHeader[len(BearerHeader):]
		if !bytes.HasPrefix(authHeader, auth.ServiceKeySessionPrefix) {
			return nil
		}

		keySplit := bytes.Split(authHeader, KeyDelimiter)
		if len(keySplit) != 2 {
			return nil
		}

		keyID := string(keySplit[0])
		keySecret := keySplit[1]

		sess, err := m.GetServiceKeySession(ctx, keyID, keySecret)
		if sess == nil {
			return err
		}

		err = m.storage.DeleteServiceKeySession(ctx.Context(), sess.ID)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to delete service key session")
			return ctx.Status(fiber.StatusInternalServerError).SendString("failed to delete service key session")
		}
	}
	return nil
}

func (m *Manager) subscribeToSecretKeyEvents(events <-chan *storage.SecretKeyEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("secret key event subscription stopped")
			return
		case event := <-events:
			m.logger.Info().Msg("secret key updated")
			m.secretKeyMu.Lock()
			m.oldSecretKey = m.secretKey
			m.secretKey = event.SecretKey
			m.secretKeyMu.Unlock()
		}
	}
}

func (m *Manager) subscribeToRegistrationEvents(events <-chan *storage.RegistrationEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("registration event subscription stopped")
			return
		case event := <-events:
			m.logger.Info().Msg("registration updated")
			m.registrationMu.Lock()
			m.registration = event.Enabled
			m.registrationMu.Unlock()
		}
	}
}

func (m *Manager) subscribeToSessionIDEvents(events <-chan *storage.SessionEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("session event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				m.logger.Debug().Msgf("session %s deleted", event.SessionID)
				m.sessionsMu.Lock()
				delete(m.sessions, event.SessionID)
				m.sessionsMu.Unlock()
			} else {
				m.logger.Debug().Msgf("session %s created", event.SessionID)
				m.sessionsMu.Lock()
				m.sessions[event.SessionID] = struct{}{}
				m.sessionsMu.Unlock()
			}
		}
	}
}

func (m *Manager) subscribeToAPIKeyEvents(events <-chan *storage.APIKeyEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("api key event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				m.logger.Debug().Msgf("api key %s deleted", event.APIKeyID)
				m.apikeysMu.Lock()
				delete(m.apikeys, event.APIKeyID)
				m.apikeysMu.Unlock()
			} else {
				m.logger.Debug().Msgf("api key %s created or updated", event.APIKeyID)
				if event.APIKey == nil {
					m.logger.Error().Msgf("api key in create or update event for api key ID %s is nil", event.APIKeyID)
				} else {
					m.apikeysMu.Lock()
					m.apikeys[event.APIKeyID] = event.APIKey
					m.apikeysMu.Unlock()
				}
			}
		}
	}
}

func (m *Manager) subscribeToServiceKeySessionEvents(events <-chan *storage.ServiceKeySessionEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("service key session event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				m.logger.Debug().Msgf("service key session %s deleted", event.ServiceKeySessionID)
				m.servicekeySessionsMu.Lock()
				delete(m.servicekeySessions, event.ServiceKeySessionID)
				m.servicekeySessionsMu.Unlock()
			} else {
				m.logger.Debug().Msgf("service key session %s created or updated", event.ServiceKeySessionID)
				if event.ServiceKeySession == nil {
					m.logger.Error().Msgf("service key session in create or update event for service key session ID %s is nil", event.ServiceKeySessionID)
				} else {
					m.servicekeySessionsMu.Lock()
					m.servicekeySessions[event.ServiceKeySessionID] = event.ServiceKeySession
					m.servicekeySessionsMu.Unlock()
				}
			}
		}
	}
}
