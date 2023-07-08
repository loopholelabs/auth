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

package storage

import (
	"context"
	"time"
)

// DeviceFlow holds the Device Code Authorization Flow
type DeviceFlow struct {
	Identifier string    `json:"identifier"`
	DeviceCode string    `json:"device_code"`
	UserCode   string    `json:"user_code"`
	Session    string    `json:"session"`
	LastPoll   time.Time `json:"last_poll"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// GithubFlow holds the Github Authorization Flow
type GithubFlow struct {
	Identifier       string `json:"identifier"`
	Verifier         string `json:"verifier"`
	Challenge        string `json:"challenge"`
	NextURL          string `json:"next_url"`
	Organization     string `json:"organization"`
	DeviceIdentifier string `json:"device_identifier"`
}

// GoogleFlow holds the Google Authorization Flow
type GoogleFlow struct {
	Identifier       string `json:"identifier"`
	Verifier         string `json:"verifier"`
	Challenge        string `json:"challenge"`
	NextURL          string `json:"next_url"`
	Organization     string `json:"organization"`
	DeviceIdentifier string `json:"device_identifier"`
}

// MagicFlow holds the Magic Authorization Flow
type MagicFlow struct {
	Identifier       string `json:"identifier"`
	Email            string `json:"email"`
	IPAddress        string `json:"ip_address"`
	Secret           string `json:"secret"`
	NextURL          string `json:"next_url"`
	Organization     string `json:"organization"`
	DeviceIdentifier string `json:"device_identifier"`
}

type Device interface {
	SetDeviceFlow(ctx context.Context, identifier string, deviceCode string, userCode string) error
	GetDeviceFlow(ctx context.Context, deviceCode string) (*DeviceFlow, error)
	UpdateDeviceFlow(ctx context.Context, identifier string, session string, expiry time.Time) error
	GetDeviceFlowUserCode(ctx context.Context, userCode string) (*DeviceFlow, error)
	GetDeviceFlowIdentifier(ctx context.Context, identifier string) (*DeviceFlow, error)
	DeleteDeviceFlow(ctx context.Context, deviceCode string) error
	GCDeviceFlow(ctx context.Context, expiry time.Duration) (int, error)
}

type Github interface {
	SetGithubFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string, deviceIdentifier string) error
	GetGithubFlow(ctx context.Context, state string) (*GithubFlow, error)
	DeleteGithubFlow(ctx context.Context, state string) error
	GCGithubFlow(ctx context.Context, expiry time.Duration) (int, error)
}

type Google interface {
	SetGoogleFlow(ctx context.Context, state string, verifier string, challenge string, nextURL string, organization string, deviceIdentifier string) error
	GetGoogleFlow(ctx context.Context, state string) (*GoogleFlow, error)
	DeleteGoogleFlow(ctx context.Context, state string) error
	GCGoogleFlow(ctx context.Context, expiry time.Duration) (int, error)
}

type Magic interface {
	SetMagicFlow(ctx context.Context, email string, ip string, secret string, nextURL string, organization string, deviceIdentifier string) error
	GetMagicFlow(ctx context.Context, email string) (*MagicFlow, error)
	DeleteMagicFlow(ctx context.Context, email string) error
	GCMagicFlow(ctx context.Context, expiry time.Duration) (int, error)
}

// Flow is the interface for storage of Authorization Flows
type Flow interface {
	Device
	Github
	Google
	Magic
}
