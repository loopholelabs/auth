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
	"github.com/loopholelabs/auth/internal/provider/device"
	"github.com/loopholelabs/auth/internal/provider/github"
	"github.com/loopholelabs/auth/internal/provider/google"
	"github.com/loopholelabs/auth/internal/provider/magic"
)

type Github func() *github.Github

type Google func() *google.Google

type Device func() *device.Device

type Magic func() *magic.Magic

type Modifier func(*Options)

func WithGithub(github Github) Modifier {
	return func(options *Options) {
		options.github = github
	}
}

func WithGoogle(google Google) Modifier {
	return func(options *Options) {
		options.google = google
	}
}

func WithDevice(device Device) Modifier {
	return func(options *Options) {
		options.device = device
	}
}

func WithMagic(magic Magic) Modifier {
	return func(options *Options) {
		options.magic = magic
	}
}

type Options struct {
	github         Github
	google         Google
	device         Device
	magic          Magic
	defaultNextURL string
	controller     *controller.Controller

	endpoint string
	tls      bool
}

func New(controller *controller.Controller, defaultNextURL string, endpoint string, tls bool, modifiers ...Modifier) *Options {
	options := &Options{
		controller:     controller,
		defaultNextURL: defaultNextURL,
		endpoint:       endpoint,
		tls:            tls,
	}

	for _, modifier := range modifiers {
		modifier(options)
	}

	if options.github == nil {
		options.github = func() *github.Github {
			return nil
		}
	}

	if options.google == nil {
		options.google = func() *google.Google {
			return nil
		}
	}

	if options.device == nil {
		options.device = func() *device.Device {
			return nil
		}
	}

	if options.magic == nil {
		options.magic = func() *magic.Magic {
			return nil
		}
	}

	return options
}

func (o *Options) GithubProvider() *github.Github {
	return o.github()
}

func (o *Options) GoogleProvider() *google.Google {
	return o.google()
}

func (o *Options) DeviceProvider() *device.Device {
	return o.device()
}

func (o *Options) MagicProvider() *magic.Magic {
	return o.magic()
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
