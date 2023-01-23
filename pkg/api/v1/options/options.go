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
	"github.com/loopholelabs/auth/pkg/manager"
	"github.com/loopholelabs/auth/pkg/provider/device"
	"github.com/loopholelabs/auth/pkg/provider/github"
	"github.com/loopholelabs/auth/pkg/provider/magic"
)

type Github func() *github.Github

type Device func() *device.Device

type Magic func() *magic.Magic

type NextURL func() string

type Modifier func(*Options)

func WithGithub(github Github) Modifier {
	return func(options *Options) {
		options.github = github
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
	github  Github
	device  Device
	magic   Magic
	nextURL NextURL
	manager *manager.Manager

	domain string
	port   int
	tls    bool
}

func New(manager *manager.Manager, nextURL NextURL, domain string, port int, tls bool, modifiers ...Modifier) *Options {
	options := &Options{
		manager: manager,
		nextURL: nextURL,
		domain:  domain,
		port:    port,
		tls:     tls,
	}

	for _, modifier := range modifiers {
		modifier(options)
	}

	if options.github == nil {
		options.github = func() *github.Github {
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

func (o *Options) Github() *github.Github {
	return o.github()
}

func (o *Options) Device() *device.Device {
	return o.device()
}

func (o *Options) Magic() *magic.Magic {
	return o.magic()
}

func (o *Options) Manager() *manager.Manager {
	return o.manager
}

func (o *Options) NextURL() string {
	return o.nextURL()
}

func (o *Options) Domain() string {
	return o.domain
}

func (o *Options) Port() int {
	return o.port
}

func (o *Options) TLS() bool {
	return o.tls
}
