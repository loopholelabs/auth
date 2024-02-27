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

package options

import (
	"github.com/loopholelabs/auth/internal/controller"
	"github.com/loopholelabs/auth/pkg/flow/device"
	"github.com/loopholelabs/auth/pkg/flow/github"
	"github.com/loopholelabs/auth/pkg/flow/google"
	"github.com/loopholelabs/auth/pkg/flow/magic"
	"github.com/rs/zerolog"
)

type Options struct {
	device         *device.Device
	github         *github.Github
	google         *google.Google
	magic          *magic.Magic
	controller     *controller.Controller
	endpoint       string
	tls            bool
	defaultNextURL string
}

func New(controller *controller.Controller, device *device.Device, github *github.Github, google *google.Google, magic *magic.Magic, endpoint string, tls bool, defaultNextURL string, logger *zerolog.Logger) *Options {
	if endpoint == "" {
		l := logger.With().Str("AUTH", "MAGIC-LINK-PROVIDER").Logger()
		l.Error().Msg("Error: base endpoint is not set for Magic Link")
	}

	return &Options{
		controller:     controller,
		device:         device,
		github:         github,
		google:         google,
		magic:          magic,
		endpoint:       endpoint,
		defaultNextURL: defaultNextURL,
	}
}

func (o *Options) GithubProvider() *github.Github {
	return o.github
}

func (o *Options) GoogleProvider() *google.Google {
	return o.google
}

func (o *Options) DeviceProvider() *device.Device {
	return o.device
}

func (o *Options) MagicProvider() *magic.Magic {
	return o.magic
}

func (o *Options) Controller() *controller.Controller {
	return o.controller
}

func (o *Options) DefaultNextURL() string {
	return o.defaultNextURL
}

func (o *Options) Endpoint() string {
	return o.endpoint
}

func (o *Options) TLS() bool {
	return o.tls
}
