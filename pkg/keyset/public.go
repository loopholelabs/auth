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

package keyset

import (
	"errors"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"time"
)

type Public struct {
	KeySet
	CachedKeys []jose.JSONWebKey
}

func (k *Public) Verify(jws *jose.JSONWebSignature) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	keys := k.keysFromCache()
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}

	// If the kid doesn't match, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	keys, err := k.keysFromStorage()
	if err != nil {
		return nil, fmt.Errorf("fetching keys %v", err)
	}

	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}
	return nil, errors.New("failed to verify token signature")
}

func (k *Public) keysFromCache() (keys []jose.JSONWebKey) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.CachedKeys
}

func (k *Public) keysFromStorage() ([]jose.JSONWebKey, error) {
	k.mu.Lock()

	if k.updater == nil {
		k.updater = &updater{
			done: make(chan struct{}),
		}

		go func() {
			keys, err := k.updateKeys()
			k.updater.keys = keys
			k.updater.err = err
			close(k.updater.done)

			k.mu.Lock()
			defer k.mu.Unlock()

			if err == nil {
				k.CachedKeys = keys
			}

			k.updater = nil
		}()
	}
	updater := k.updater
	k.mu.Unlock()

	t := time.NewTimer(time.Second * 30)

	select {
	case <-t.C:
		t.Stop()
		return nil, errors.New("updating keys timed out")
	case <-updater.done:
		t.Stop()
		return updater.keys, updater.err
	}
}

func (k *Public) updateKeys() ([]jose.JSONWebKey, error) {
	keys, err := k.storage.GetKeys()
	if err != nil {
		return nil, err
	}

	if keys.SigningKeyPub == nil {
		return nil, errors.New("no public key found")
	}

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keys.VerificationKeys)+1),
	}
	jwks.Keys[0] = *keys.SigningKeyPub
	for i, verificationKey := range keys.VerificationKeys {
		jwks.Keys[i+1] = *verificationKey.PublicKey
	}
	return jwks.Keys, nil
}
