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

type Private struct {
	KeySet
	CachedKey    jose.JSONWebKey
	NextRotation time.Time
}

func (k *Private) Sign(alg jose.SignatureAlgorithm, payload []byte) (string, error) {
	var signingKey jose.SigningKey
	k.mu.Lock()
	if time.Now().Before(k.NextRotation) {
		signingKey = jose.SigningKey{Key: &k.CachedKey, Algorithm: alg}
		k.mu.Unlock()
	} else {
		k.mu.Unlock()
		key, err := k.keyFromStorage()
		if err != nil {
			return "", fmt.Errorf("fetching keys %v", err)
		}
		signingKey = jose.SigningKey{Key: &key, Algorithm: alg}
	}
	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signature.CompactSerialize()
}

func (k *Private) keyFromStorage() (jose.JSONWebKey, error) {
	k.mu.Lock()

	if k.updater == nil {
		k.updater = &updater{
			done: make(chan struct{}),
		}

		go func() {
			key, rotation, err := k.updateKey()
			k.updater.keys = []jose.JSONWebKey{key}
			k.updater.rotation = rotation
			k.updater.err = err
			close(k.updater.done)

			k.mu.Lock()
			defer k.mu.Unlock()

			if err == nil {
				k.CachedKey = key
				k.NextRotation = rotation
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
		return jose.JSONWebKey{}, errors.New("updating keys timed out")
	case <-updater.done:
		t.Stop()
		return updater.keys[0], updater.err
	}
}

func (k *Private) updateKey() (jose.JSONWebKey, time.Time, error) {
	keys, err := k.storage.GetKeys()
	if err != nil {
		return jose.JSONWebKey{}, time.Time{}, err
	}

	if keys.SigningKey == nil {
		return jose.JSONWebKey{}, time.Time{}, errors.New("no signing key found")
	}

	return *keys.SigningKey, keys.NextRotation, nil
}
