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

package device

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/loopholelabs/auth/internal/utils"
	"github.com/loopholelabs/auth/pkg/flow"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/rs/zerolog"
	"strings"
	"sync"
	"time"
)

var _ flow.Flow = (*Device)(nil)

const (
	Key        flow.Key = "device"
	GCInterval          = time.Minute
	Expiry              = time.Minute * 5
)

type Device struct {
	logger  *zerolog.Logger
	storage storage.Device
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func New(storage storage.Device, logger *zerolog.Logger) *Device {
	l := logger.With().Str("AUTH", "DEVICE-FLOW").Logger()
	ctx, cancel := context.WithCancel(context.Background())

	return &Device{
		logger:  &l,
		storage: storage,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (g *Device) Key() flow.Key {
	return Key
}

func (g *Device) Start() error {
	g.wg.Add(1)
	go g.gc()
	return nil
}

func (g *Device) Stop() error {
	g.cancel()
	g.wg.Wait()
	return nil
}

func (g *Device) StartFlow(ctx context.Context) (string, string, error) {
	deviceCode := strings.ToUpper(utils.RandomString(8))
	userCode := uuid.New().String()
	identifier := uuid.New().String()

	err := g.storage.SetDeviceFlow(ctx, identifier, deviceCode, userCode)
	if err != nil {
		return "", "", err
	}

	return deviceCode, userCode, nil
}

func (g *Device) ValidateFlow(ctx context.Context, deviceCode string) (string, error) {
	f, err := g.storage.GetDeviceFlow(ctx, deviceCode)
	if err != nil {
		return "", err
	}

	return f.Identifier, nil
}

func (g *Device) FlowExists(ctx context.Context, identifier string) (bool, error) {
	_, err := g.storage.GetDeviceFlowIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (g *Device) PollFlow(ctx context.Context, userCode string) (string, time.Time, time.Time, error) {
	f, err := g.storage.GetDeviceFlowUserCode(ctx, userCode)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}

	if f.Session != "" {
		err = g.storage.DeleteDeviceFlow(ctx, f.DeviceCode)
		if err != nil {
			return "", time.Time{}, time.Time{}, err
		}
	}

	return f.Session, f.ExpiresAt, f.LastPoll, nil
}

func (g *Device) CompleteFlow(ctx context.Context, identifier string, session string, expiry time.Time) error {
	err := g.storage.UpdateDeviceFlow(ctx, identifier, session, expiry)
	if err != nil {
		return err
	}

	return nil
}

func (g *Device) gc() {
	defer g.wg.Done()
	for {
		select {
		case <-g.ctx.Done():
			g.logger.Info().Msg("GC Stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := g.storage.GCDeviceFlow(g.ctx, Expiry)
			if err != nil {
				g.logger.Error().Err(err).Msg("failed to garbage collect expired device flows")
			} else {
				g.logger.Debug().Msgf("garbage collected %d expired device flows", deleted)
			}
		}
	}
}
