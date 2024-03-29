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

package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/auth/internal/aes"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/apikey"
	"github.com/loopholelabs/auth/pkg/claims"
	"github.com/loopholelabs/auth/pkg/flow"
	"github.com/loopholelabs/auth/pkg/key"
	"github.com/loopholelabs/auth/pkg/kind"
	"github.com/loopholelabs/auth/pkg/magic"
	"github.com/loopholelabs/auth/pkg/prefix"
	"github.com/loopholelabs/auth/pkg/servicesession"
	"github.com/loopholelabs/auth/pkg/session"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
	"sync"
	"time"
)

var (
	ErrInvalidContext = errors.New("invalid context")
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

	EmptySecretKey = [32]byte{}
)

type Controller struct {
	logger            *zerolog.Logger
	storage           storage.Storage
	sessionDomain     string
	secureOnlyCookies bool
	wg                sync.WaitGroup
	ctx               context.Context
	cancel            context.CancelFunc

	secretKey    [32]byte
	oldSecretKey [32]byte
	secretKeyMu  sync.RWMutex

	registration   bool
	registrationMu sync.RWMutex

	sessions   map[string]struct{}
	sessionsMu sync.RWMutex

	serviceSessions   map[string]*servicesession.ServiceSession
	serviceSessionsMu sync.RWMutex

	apikeys   map[string]*apikey.APIKey
	apikeysMu sync.RWMutex
}

func New(sessionDomain string, secureOnlyCookies bool, storage storage.Storage, logger *zerolog.Logger) *Controller {
	l := logger.With().Str("AUTH", "SESSION-CONTROLLER").Logger()
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{
		logger:            &l,
		storage:           storage,
		sessionDomain:     sessionDomain,
		secureOnlyCookies: secureOnlyCookies,
		ctx:               ctx,
		cancel:            cancel,
		sessions:          make(map[string]struct{}),
		serviceSessions:   make(map[string]*servicesession.ServiceSession),
		apikeys:           make(map[string]*apikey.APIKey),
	}
}

func (m *Controller) Start() error {
	m.logger.Info().Msg("starting manager")

	m.secretKeyMu.Lock()
	secretKeyEvents := m.storage.SubscribeToSecretKey(m.ctx)
	m.wg.Add(1)
	go m.subscribeToSecretKeyEvents(secretKeyEvents)
	m.logger.Info().Msg("subscribed to secret key events")
	var err error
	m.secretKey, err = m.storage.GetSecretKey(m.ctx)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			m.logger.Info().Msg("no secret key found, generating new one")
			m.secretKey = [32]byte(utils.RandomBytes(32))
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
	registrationEvents := m.storage.SubscribeToRegistration(m.ctx)
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
	sessionEvents := m.storage.SubscribeToSessions(m.ctx)
	m.wg.Add(1)
	go m.subscribeToSessionEvents(sessionEvents)
	m.logger.Info().Msg("subscribed to session events")
	sessions, err := m.storage.ListSessions(m.ctx)
	if err != nil {
		m.sessionsMu.Unlock()
		return fmt.Errorf("failed to list session IDs: %w", err)
	}
	for _, sess := range sessions {
		m.sessions[sess.Identifier] = struct{}{}
	}
	m.sessionsMu.Unlock()
	m.logger.Info().Msg("retrieved sessions")

	m.serviceSessionsMu.Lock()
	serviceSessionEvents := m.storage.SubscribeToServiceSessions(m.ctx)
	m.wg.Add(1)
	go m.subscribeToServiceSessionEvents(serviceSessionEvents)
	m.logger.Info().Msg("subscribed to service session events")
	serviceSessions, err := m.storage.ListServiceSessions(m.ctx)
	if err != nil {
		m.serviceSessionsMu.Unlock()
		return fmt.Errorf("failed to list service sessions: %w", err)
	}
	for _, sess := range serviceSessions {
		m.serviceSessions[sess.Identifier] = sess
	}
	m.serviceSessionsMu.Unlock()
	m.logger.Info().Msg("retrieved service sessions")

	m.apikeysMu.Lock()
	apikeyEvents := m.storage.SubscribeToAPIKeys(m.ctx)
	m.wg.Add(1)
	go m.subscribeToAPIKeyEvents(apikeyEvents)
	m.logger.Info().Msg("subscribed to api key events")
	apikeys, err := m.storage.ListAPIKeys(m.ctx)
	if err != nil {
		m.apikeysMu.Unlock()
		return fmt.Errorf("failed to list api keys: %w", err)
	}
	for _, k := range apikeys {
		m.apikeys[k.Identifier] = k
	}
	m.apikeysMu.Unlock()
	m.logger.Info().Msg("retrieved api keys")

	return nil
}

func (m *Controller) Stop() error {
	m.logger.Info().Msg("stopping manager")
	m.cancel()
	m.wg.Wait()
	return nil
}

func (m *Controller) GenerateCookie(session string, expiry time.Time) *fiber.Cookie {
	m.logger.Debug().Msgf("generating cookie with expiry %s", expiry)
	return &fiber.Cookie{
		Name:     CookieKeyString,
		Value:    session,
		Domain:   m.sessionDomain,
		Expires:  expiry,
		Secure:   m.secureOnlyCookies,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	}
}

func (m *Controller) EncodeMagic(email string, secret []byte) (string, error) {
	data, err := json.Marshal(&magic.Magic{
		Email:  email,
		Secret: secret,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal magic: %w", err)
	}

	return base64.URLEncoding.EncodeToString(data), nil
}

func (m *Controller) DecodeMagic(encoded string) (string, []byte, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode magic link token: %w", err)
	}

	ma := new(magic.Magic)
	err = json.Unmarshal(data, ma)
	if err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal magic: %w", err)
	}

	return ma.Email, ma.Secret, nil
}

func (m *Controller) CreateSession(ctx *fiber.Ctx, device bool, provider flow.Key, userID string, organization string) (*fiber.Cookie, string, error) {
	m.logger.Debug().Msgf("creating session for user %s (org '%s')", userID, organization)

	exists, err := m.storage.UserExists(ctx.Context(), userID)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to check if user exists")
		return nil, "", ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if user exists")
	}

	if !exists {
		if organization != "" {
			return nil, "", ctx.Status(fiber.StatusNotFound).SendString("user does not exist")
		}

		m.logger.Debug().Msgf("user %s does not exist", userID)
		m.registrationMu.RLock()
		registration := m.registration
		m.registrationMu.RUnlock()

		if !registration {
			return nil, "", ctx.Status(fiber.StatusNotFound).SendString("user does not exist")
		}

		m.logger.Debug().Msgf("creating user %s", userID)

		c := &claims.Claims{
			Identifier: userID,
		}

		err = m.storage.NewUser(ctx.Context(), c)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to create user")
			return nil, "", ctx.Status(fiber.StatusInternalServerError).SendString("failed to create user")
		}
	}

	if organization != "" {
		m.logger.Debug().Msgf("checking if user %s is member of organization %s", userID, organization)
		exists, err = m.storage.UserOrganizationExists(ctx.Context(), userID, organization)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to check if organization exists")
			return nil, "", ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if organization exists")
		}

		if !exists {
			return nil, "", ctx.Status(fiber.StatusForbidden).SendString("invalid organization")
		}
	} else {
		organization, err = m.storage.UserDefaultOrganization(ctx.Context(), userID)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to get user's default organization")
			return nil, "", ctx.Status(fiber.StatusInternalServerError).SendString("failed to get user's default organization")
		}
	}

	sess := session.New(device, provider, userID, organization)
	data, err := json.Marshal(sess)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to marshal session")
		return nil, "", ctx.Status(fiber.StatusInternalServerError).SendString("failed to marshal session")
	}

	m.secretKeyMu.RLock()
	secretKey := m.secretKey
	m.secretKeyMu.RUnlock()

	encrypted, err := aes.Encrypt(secretKey, CookieKey, data)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to encrypt session")
		return nil, "", ctx.Status(fiber.StatusInternalServerError).SendString("failed to encrypt session")
	}

	err = m.storage.SetSession(ctx.Context(), sess)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to set session")
		return nil, "", ctx.Status(fiber.StatusInternalServerError).SendString("failed to set session")
	}

	m.logger.Debug().Msgf("created session %s for owner %s (org '%s') with expiry %s", sess.Identifier, sess.Creator, sess.Organization, sess.Expiry)

	return m.GenerateCookie(encrypted, sess.Expiry), sess.Identifier, nil
}

func (m *Controller) CreateServiceSession(ctx *fiber.Ctx, keyID string, keySecret []byte) (*servicesession.ServiceSession, []byte, error) {
	serviceKey, err := m.storage.GetServiceKey(ctx.Context(), keyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, ctx.Status(fiber.StatusUnauthorized).SendString("service key does not exist")
		}
		m.logger.Error().Err(err).Msg("failed to check if service key exists")
		return nil, nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if service key exists")
	}

	if bcrypt.CompareHashAndPassword(serviceKey.Hash, append(serviceKey.Salt, keySecret...)) != nil {
		return nil, nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid service key")
	}

	if !serviceKey.Expires.IsZero() && time.Now().After(serviceKey.Expires) {
		return nil, nil, ctx.Status(fiber.StatusUnauthorized).SendString("service key expired")
	}

	if serviceKey.MaxUses != 0 && serviceKey.NumUsed >= serviceKey.MaxUses {
		return nil, nil, ctx.Status(fiber.StatusUnauthorized).SendString("service key has reached its maximum uses")
	}

	err = m.storage.IncrementServiceKeyNumUsed(ctx.Context(), serviceKey.Identifier, 1)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to increment service key num used")
		return nil, nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to increment service key num used")
	}

	sess, secret, err := servicesession.New(serviceKey)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to create service session")
		return nil, nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to create service session")
	}

	err = m.storage.SetServiceSession(ctx.Context(), sess.Identifier, sess.Salt, sess.Hash, sess.ServiceKeyIdentifier)
	if err != nil {
		m.logger.Error().Err(err).Msg("failed to set service session")
		return nil, nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to set service session")
	}

	m.logger.Debug().Msgf("created service session %s for user %s (org '%s')", sess.Identifier, sess.Creator, sess.Organization)

	return sess, secret, nil
}

func (m *Controller) Validate(ctx *fiber.Ctx) error {
	cookie := ctx.Cookies(CookieKeyString)
	if cookie != "" {
		sess, err := m.getSession(ctx, cookie)
		if sess == nil {
			return err
		}

		ctx.Locals(key.KindContext, kind.Session)
		ctx.Locals(key.SessionContext, sess)
		ctx.Locals(key.UserContext, sess.Creator)
		ctx.Locals(key.OrganizationContext, sess.Organization)
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

		if bytes.HasPrefix(authHeader, prefix.APIKey) {
			k, err := m.getAPIKey(ctx, keyID, keySecret)
			if k == nil {
				return err
			}

			ctx.Locals(key.KindContext, kind.APIKey)
			ctx.Locals(key.APIKeyContext, k)
			ctx.Locals(key.UserContext, k.Creator)
			ctx.Locals(key.OrganizationContext, k.Organization)
			return ctx.Next()
		}

		if bytes.HasPrefix(authHeader, prefix.ServiceSession) {
			serviceSession, err := m.getServiceSession(ctx, keyID, keySecret)
			if serviceSession == nil {
				return err
			}

			ctx.Locals(key.KindContext, kind.ServiceSession)
			ctx.Locals(key.ServiceSessionContext, serviceSession)
			ctx.Locals(key.UserContext, serviceSession.Creator)
			ctx.Locals(key.OrganizationContext, serviceSession.Organization)
			return ctx.Next()
		}
	}

	return ctx.Status(fiber.StatusUnauthorized).SendString("no valid session cookie or authorization header")
}

func (m *Controller) ManualValidate(ctx *fiber.Ctx) (bool, error) {
	cookie := ctx.Cookies(CookieKeyString)
	if cookie != "" {
		sess, err := m.getSession(ctx, cookie)
		if sess == nil {
			return false, err
		}

		ctx.Locals(key.KindContext, kind.Session)
		ctx.Locals(key.SessionContext, sess)
		ctx.Locals(key.UserContext, sess.Organization)
		ctx.Locals(key.OrganizationContext, sess.Organization)
		return true, nil
	}

	authHeader := ctx.Request().Header.PeekBytes(AuthorizationHeader)
	if len(authHeader) > len(BearerHeader) {
		if !bytes.Equal(authHeader[:len(BearerHeader)], BearerHeader) {
			return false, ctx.Status(fiber.StatusUnauthorized).SendString("invalid authorization header")
		}
		authHeader = authHeader[len(BearerHeader):]
		keySplit := bytes.Split(authHeader, KeyDelimiter)
		if len(keySplit) != 2 {
			return false, ctx.Status(fiber.StatusUnauthorized).SendString("invalid authorization header")
		}

		keyID := string(keySplit[0])
		keySecret := keySplit[1]

		if bytes.HasPrefix(authHeader, prefix.APIKey) {
			k, err := m.getAPIKey(ctx, keyID, keySecret)
			if k == nil {
				return false, err
			}

			ctx.Locals(key.KindContext, kind.APIKey)
			ctx.Locals(key.APIKeyContext, k)
			ctx.Locals(key.UserContext, k.Creator)
			ctx.Locals(key.OrganizationContext, k.Organization)
			return true, nil
		}

		if bytes.HasPrefix(authHeader, prefix.ServiceSession) {
			serviceSession, err := m.getServiceSession(ctx, keyID, keySecret)
			if serviceSession == nil {
				return false, err
			}

			ctx.Locals(key.KindContext, kind.ServiceSession)
			ctx.Locals(key.ServiceSessionContext, serviceSession)
			ctx.Locals(key.UserContext, serviceSession.Creator)
			ctx.Locals(key.OrganizationContext, serviceSession.Organization)
			return true, nil
		}
	}

	return false, ctx.Status(fiber.StatusUnauthorized).SendString("no valid session cookie or authorization header")
}

func (m *Controller) LogoutSession(ctx *fiber.Ctx) (bool, error) {
	cookie := ctx.Cookies(CookieKeyString)
	if cookie != "" {
		sess, err := m.getSession(ctx, cookie)
		if sess == nil {
			return false, err
		}
		err = m.storage.DeleteSession(ctx.Context(), sess.Identifier)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to delete session")
			return false, ctx.Status(fiber.StatusInternalServerError).SendString("failed to delete session")
		}
	}

	ctx.ClearCookie(CookieKeyString)
	return true, nil
}

func (m *Controller) LogoutServiceSession(ctx *fiber.Ctx) (bool, error) {
	authHeader := ctx.Request().Header.PeekBytes(AuthorizationHeader)
	if len(authHeader) > len(BearerHeader) {
		if !bytes.Equal(authHeader[:len(BearerHeader)], BearerHeader) {
			return true, nil
		}

		authHeader = authHeader[len(BearerHeader):]
		if !bytes.HasPrefix(authHeader, prefix.ServiceSession) {
			return true, nil
		}

		keySplit := bytes.Split(authHeader, KeyDelimiter)
		if len(keySplit) != 2 {
			return true, nil
		}

		keyID := string(keySplit[0])
		keySecret := keySplit[1]

		sess, err := m.getServiceSession(ctx, keyID, keySecret)
		if sess == nil {
			return false, err
		}

		err = m.storage.DeleteServiceSession(ctx.Context(), sess.Identifier)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to delete service session")
			return false, ctx.Status(fiber.StatusInternalServerError).SendString("failed to delete service session")
		}
	}
	return true, nil
}

func (m *Controller) SubscriptionHealthy() bool {
	errs := m.storage.Errors()
	ret := true

	if errs.APIKeyError != nil {
		m.logger.Error().Err(errs.APIKeyError).Msg("storage error for api keys")
		ret = false
	}

	if errs.ServiceSessionError != nil {
		m.logger.Error().Err(errs.ServiceSessionError).Msg("storage error for service sessions")
		ret = false
	}

	if errs.SessionError != nil {
		m.logger.Error().Err(errs.SessionError).Msg("storage error for sessions")
		ret = false
	}

	if errs.RegistrationError != nil {
		m.logger.Error().Err(errs.RegistrationError).Msg("storage error for registrations")
		ret = false
	}

	if errs.SecretKeyError != nil {
		m.logger.Error().Err(errs.SecretKeyError).Msg("storage error for secret keys")
		ret = false
	}

	return ret
}

func (m *Controller) getSession(ctx *fiber.Ctx, cookie string) (*session.Session, error) {
	m.secretKeyMu.RLock()
	secretKey := m.secretKey
	oldSecretKey := m.oldSecretKey
	m.secretKeyMu.RUnlock()

	oldSecretKeyUsed := false
	decrypted, err := aes.Decrypt(secretKey, CookieKey, cookie)
	if err != nil {
		if errors.Is(err, aes.ErrInvalidContent) {
			if oldSecretKey != EmptySecretKey {
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
	_, exists := m.sessions[sess.Identifier]
	m.sessionsMu.RUnlock()
	if !exists {
		_, err = m.storage.GetSession(ctx.Context(), sess.Identifier)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ctx.Status(fiber.StatusUnauthorized).SendString("session does not exist")
			}
			m.logger.Error().Err(err).Msg("failed to check if session exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if session exists")
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

		err = m.storage.UpdateSessionExpiry(ctx.Context(), sess.Identifier, sess.Expiry)
		if err != nil {
			m.logger.Error().Err(err).Msg("failed to update session expiry")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to update session expiry")
		}

		ctx.Cookie(m.GenerateCookie(encrypted, sess.Expiry))
	}

	return sess, nil
}

func (m *Controller) getAPIKey(ctx *fiber.Ctx, keyID string, keySecret []byte) (*apikey.APIKey, error) {
	m.apikeysMu.RLock()
	k, ok := m.apikeys[keyID]
	m.apikeysMu.RUnlock()
	if !ok {
		var err error
		k, err = m.storage.GetAPIKey(ctx.Context(), keyID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ctx.Status(fiber.StatusUnauthorized).SendString("api key does not exist")
			}
			m.logger.Error().Err(err).Msg("failed to check if api key exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if api key exists")
		}
	}

	if bcrypt.CompareHashAndPassword(k.Hash, append(k.Salt, keySecret...)) != nil {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid api key")
	}

	return k, nil
}

func (m *Controller) getServiceSession(ctx *fiber.Ctx, sessionID string, sessionSecret []byte) (*servicesession.ServiceSession, error) {
	m.serviceSessionsMu.RLock()
	sess, ok := m.serviceSessions[sessionID]
	m.serviceSessionsMu.RUnlock()
	if !ok {
		var err error
		sess, err = m.storage.GetServiceSession(ctx.Context(), sessionID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, ctx.Status(fiber.StatusUnauthorized).SendString("service session does not exist")
			}
			m.logger.Error().Err(err).Msg("failed to check if service session exists")
			return nil, ctx.Status(fiber.StatusInternalServerError).SendString("failed to check if service session exists")
		}
	}

	if bcrypt.CompareHashAndPassword(sess.Hash, append(sess.Salt, sessionSecret...)) != nil {
		return nil, ctx.Status(fiber.StatusUnauthorized).SendString("invalid service session")
	}

	return sess, nil
}

func (m *Controller) subscribeToSecretKeyEvents(events <-chan storage.SecretKeyEvent) {
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
			m.secretKey = event
			m.secretKeyMu.Unlock()
		}
	}
}

func (m *Controller) subscribeToRegistrationEvents(events <-chan *storage.RegistrationEvent) {
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

func (m *Controller) subscribeToSessionEvents(events <-chan *storage.SessionEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("session event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				m.logger.Debug().Msgf("session %s deleted", event.Identifier)
				m.sessionsMu.Lock()
				delete(m.sessions, event.Identifier)
				m.sessionsMu.Unlock()
			} else {
				m.logger.Debug().Msgf("session %s created", event.Identifier)
				m.sessionsMu.Lock()
				m.sessions[event.Identifier] = struct{}{}
				m.sessionsMu.Unlock()
			}
		}
	}
}

func (m *Controller) subscribeToAPIKeyEvents(events <-chan *storage.APIKeyEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("api key event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				m.logger.Debug().Msgf("api key %s deleted", event.Identifier)
				m.apikeysMu.Lock()
				delete(m.apikeys, event.Identifier)
				m.apikeysMu.Unlock()
			} else {
				m.logger.Debug().Msgf("api key %s created or updated", event.Identifier)
				if event.APIKey == nil {
					m.logger.Error().Msgf("api key in create or update event for api key ID %s is nil", event.Identifier)
				} else {
					m.apikeysMu.Lock()
					m.apikeys[event.Identifier] = event.APIKey
					m.apikeysMu.Unlock()
				}
			}
		}
	}
}

func (m *Controller) subscribeToServiceSessionEvents(events <-chan *storage.ServiceSessionEvent) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info().Msg("service session event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				m.logger.Debug().Msgf("service session %s deleted", event.Identifier)
				m.serviceSessionsMu.Lock()
				delete(m.serviceSessions, event.Identifier)
				m.serviceSessionsMu.Unlock()
			} else {
				m.logger.Debug().Msgf("service session %s created or updated", event.Identifier)
				if event.ServiceSession == nil {
					m.logger.Error().Msgf("service session in create or update event for service session ID %s is nil", event.Identifier)
				} else {
					m.serviceSessionsMu.Lock()
					m.serviceSessions[event.Identifier] = event.ServiceSession
					m.serviceSessionsMu.Unlock()
				}
			}
		}
	}
}
