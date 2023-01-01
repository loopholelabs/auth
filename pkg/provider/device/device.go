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
	"github.com/google/uuid"
	"github.com/loopholelabs/auth/pkg/provider"
	"github.com/loopholelabs/auth/pkg/utils"
	"github.com/rs/zerolog"
	"sync"
	"time"
)

var _ provider.Provider = (*Device)(nil)

const (
	Key        = "device"
	GCInterval = time.Minute
	Expiry     = time.Minute * 5
)

type Device struct {
	logger   *zerolog.Logger
	database Database
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

func New(database Database, logger *zerolog.Logger) *Device {
	l := logger.With().Str("AUTH", "DEVICE-FLOW").Logger()
	ctx, cancel := context.WithCancel(context.Background())

	return &Device{
		logger:   &l,
		database: database,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (g *Device) Key() provider.Key {
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
	deviceCode := utils.RandomString(8)
	userCode := uuid.New().String()
	identifier := uuid.New().String()

	err := g.database.SetDeviceFlow(ctx, identifier, deviceCode, userCode)
	if err != nil {
		return "", "", err
	}

	return deviceCode, userCode, nil
}

func (g *Device) ValidateFlow(ctx context.Context, deviceCode string) (string, error) {
	flow, err := g.database.GetDeviceFlow(ctx, deviceCode)
	if err != nil {
		return "", err
	}

	return flow.Identifier, nil
}

func (g *Device) PollFlow(ctx context.Context, userCode string) (string, time.Time, time.Time, error) {
	flow, err := g.database.GetDeviceFlowUserCode(ctx, userCode)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}

	if flow.Session != "" {
		err = g.database.DeleteDeviceFlow(ctx, flow.DeviceCode)
		if err != nil {
			return "", time.Time{}, time.Time{}, err
		}
	}

	return flow.Session, flow.ExpiresAt, flow.LastPoll, nil
}

func (g *Device) CompleteFlow(ctx context.Context, identifier string, session string, expiry time.Time) error {
	err := g.database.UpdateDeviceFlow(ctx, identifier, session, expiry)
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
			deleted, err := g.database.GCDeviceFlow(g.ctx, Expiry)
			if err != nil {
				g.logger.Error().Err(err).Msg("failed to garbage collect expired device flows")
			} else {
				g.logger.Debug().Msgf("garbage collected %d expired device flows", deleted)
			}
		}
	}
}
