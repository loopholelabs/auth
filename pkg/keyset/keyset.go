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
	"github.com/dexidp/dex/storage"
	"gopkg.in/square/go-jose.v2"
	"sync"
	"time"
)

type KeySet struct {
	storage storage.Storage
	updater *updater
	mu      sync.RWMutex
}

type updater struct {
	done     chan struct{}
	keys     []jose.JSONWebKey
	rotation time.Time
	err      error
}

type Verifier interface {
	Verify(jws *jose.JSONWebSignature) ([]byte, error)
}

func NewPublic(storage storage.Storage) *Public {
	return &Public{
		KeySet: KeySet{
			storage: storage,
		},
	}
}

func NewPrivate(storage storage.Storage) *Private {
	return &Private{
		KeySet: KeySet{
			storage: storage,
		},
	}
}

func NewRemote(jwksURL string) *Remote {
	return newRemote(jwksURL, time.Now)
}
