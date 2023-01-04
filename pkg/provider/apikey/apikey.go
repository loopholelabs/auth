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

package apikey

import (
	"context"
	"errors"
	"github.com/loopholelabs/auth/pkg/provider"
	"github.com/rs/zerolog"
	"strings"
)

var _ provider.Provider = (*APIKey)(nil)

var (
	ErrInvalidFormat = errors.New("invalid api key format")
)

const (
	Key = "apikey"
)

type APIKey struct {
	logger  *zerolog.Logger
	storage Storage
}

func New(storage Storage, logger *zerolog.Logger) *APIKey {
	l := logger.With().Str("AUTH", "APIKEY-FLOW").Logger()
	return &APIKey{
		logger:  &l,
		storage: storage,
	}
}

func (g *APIKey) Key() provider.Key {
	return Key
}

func (g *APIKey) Start() error {
	return nil
}

func (g *APIKey) Stop() error {
	return nil
}

func (g *APIKey) Validate(ctx context.Context, apikey string) (bool, error) {
	split := strings.Split(apikey, ".")
	if len(split) != 2 {
		return false, ErrInvalidFormat
	}

	valid, err := g.storage.ValidAPIKey(ctx, split[0], split[1])
	if err != nil {
		return false, err
	}

	return valid, nil
}
