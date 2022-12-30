/*
	Copyright 2022 Loophole Labs

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

package session

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/aes"
	"github.com/loopholelabs/auth/pkg/provider"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
	"sync"
)

const (
	LocalKey = "session"
)

var (
	KeyString = "auth-session"
	Key       = []byte(KeyString)
)

type Manager struct {
	logger  *zerolog.Logger
	storage storage.Storage
	domain  string
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	secretKey    []byte
	oldSecretKey []byte
	secretKeyMu  sync.RWMutex

	sessions   map[string]struct{}
	sessionsMu sync.RWMutex
}

func NewManager(domain string, storage storage.Storage, logger *zerolog.Logger) *Manager {
	l := logger.With().Str("AUTH", "SESSION-MANAGER").Logger()
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		logger:   &l,
		storage:  storage,
		domain:   domain,
		ctx:      ctx,
		cancel:   cancel,
		sessions: make(map[string]struct{}),
	}
}

func (m *Manager) Start() error {
	m.secretKeyMu.Lock()
	secretKeyEvents, err := m.storage.SubscribeToSecretKey(m.ctx)
	if err != nil {
		m.secretKeyMu.Unlock()
		return err
	}

	m.wg.Add(1)
	go m.subscribeToSecretKeyEvents(secretKeyEvents)

	m.secretKey, err = m.storage.GetSecretKey(m.ctx)
	m.secretKeyMu.Unlock()
	if err != nil {
		return err
	}

	m.sessionsMu.Lock()
	sessionEvents, err := m.storage.SubscribeToSessions(m.ctx)
	if err != nil {
		m.sessionsMu.Unlock()
		return err
	}

	m.wg.Add(1)
	go m.subscribeToSessionEvents(sessionEvents)

	sessions, err := m.storage.ListSessions(m.ctx)
	if err != nil {
		m.sessionsMu.Unlock()
		return err
	}

	for _, session := range sessions {
		m.sessions[session] = struct{}{}
	}
	m.sessionsMu.Unlock()

	return nil
}

func (m *Manager) Stop() error {
	m.cancel()
	m.wg.Wait()
	return nil
}

func (m *Manager) Session(ctx *fiber.Ctx, provider provider.Key, userID string, organization string) (bool, error) {
	exists, err := m.storage.UserExists(ctx.Context(), userID)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to check if user exists")
		return false, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if user exists")
	}

	if !exists {
		return false, ctx.Status(fiber.StatusNotFound).SendString("user does not exist")
	}

	if organization != "" {
		exists, err = m.storage.UserOrganizationExists(ctx.Context(), userID, organization)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to check if organization exists")
			return false, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if organization exists")
		}

		if !exists {
			return false, ctx.Status(fiber.StatusForbidden).SendString("invalid organization")
		}
	}

	session := NewSession(provider, userID, organization)
	data, err := json.Marshal(session)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to marshal session")
		return false, ctx.Status(fiber.StatusInternalServerError).SendString("failed to marshal session")
	}

	m.secretKeyMu.RLock()
	secretKey := m.secretKey
	m.secretKeyMu.RUnlock()

	encrypted, err := aes.Encrypt(secretKey, Key, data)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to encrypt session")
		return false, ctx.Status(fiber.StatusInternalServerError).SendString("failed to encrypt session")
	}

	err = m.storage.SetSession(ctx.Context(), session.ID, session.UserID, session.Organization, session.Expiry)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to set session")
		return false, ctx.Status(fiber.StatusInternalServerError).SendString("failed to set session")
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     KeyString,
		Value:    string(encrypted),
		Domain:   m.domain,
		Expires:  session.Expiry,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})

	return true, nil
}

func (m *Manager) GetSession(ctx *fiber.Ctx) (*Session, error) {
	cookie := ctx.Cookies(KeyString)
	if cookie == "" {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("no session cookie")
	}

	m.secretKeyMu.RLock()
	secretKey := m.secretKey
	oldSecretKey := m.oldSecretKey
	m.secretKeyMu.RUnlock()

	decrypted, err := aes.Decrypt(secretKey, Key, []byte(cookie))
	if err != nil {
		if errors.Is(err, aes.ErrInvalidContent) {
			if oldSecretKey != nil {
				decrypted, err = aes.Decrypt(oldSecretKey, Key, []byte(cookie))
				if err != nil {
					if errors.Is(err, aes.ErrInvalidContent) {
						return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid session cookie")
					}
					m.logger.Error().Err(err).Msg("failed to decrypt session with old secret key")
					return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to decrypt session")
				}
			} else {
				return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid session cookie")
			}
		} else {
			m.logger.Error().Err(err).Msg("failed to decrypt session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to decrypt session")
		}
	}

	session := new(Session)
	err = json.Unmarshal(decrypted, session)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to unmarshal session")
		return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to unmarshal session")
	}

	if session.Expired() {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("session expired")
	}

	m.sessionsMu.RLock()
	_, exists := m.sessions[session.ID]
	m.sessionsMu.RUnlock()
	if !exists {
		exists, err = m.storage.SessionExists(ctx.Context(), session.ID)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to check if session exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if session exists")
		}
		if !exists {
			return nil, ctx.Status(fiber.StatusUnauthorized).SendString("session does not exist")
		}
	}

	if session.CloseToExpiry() {
		session.Refresh()
		data, err := json.Marshal(session)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to marshal refreshed session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to marshal session")
		}

		encrypted, err := aes.Encrypt(secretKey, Key, data)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to encrypt refreshed session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to encrypt session")
		}

		err = m.storage.SetSession(ctx.Context(), session.ID, session.UserID, session.Organization, session.Expiry)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to set refreshed session")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to set session")
		}

		ctx.Cookie(&fiber.Cookie{
			Name:     KeyString,
			Value:    string(encrypted),
			Domain:   m.domain,
			Expires:  session.Expiry,
			Secure:   true,
			HTTPOnly: true,
			SameSite: fiber.CookieSameSiteLaxMode,
		})
	}

	return session, nil
}

func (m *Manager) Validate(ctx *fiber.Ctx) error {
	session, err := m.GetSession(ctx)
	if session == nil {
		return err
	}
	ctx.Locals(LocalKey, session)
	return ctx.Next()
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

func (m *Manager) subscribeToSessionEvents(events <-chan *storage.SessionEvent) {
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
