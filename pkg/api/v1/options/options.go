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
	"github.com/loopholelabs/auth/pkg/provider/apikey"
	"github.com/loopholelabs/auth/pkg/provider/device"
	"github.com/loopholelabs/auth/pkg/provider/github"
)

type Github func() *github.Github

type Device func() *device.Device

type APIKey func() *apikey.APIKey

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

func WithAPIKey(apikey APIKey) Modifier {
	return func(options *Options) {
		options.apikey = apikey
	}
}

type Options struct {
	github  Github
	device  Device
	apikey  APIKey
	nextURL NextURL
	manager *manager.Manager
}

func New(manager *manager.Manager, nextURL NextURL, modifiers ...Modifier) *Options {
	options := &Options{
		manager: manager,
		nextURL: nextURL,
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

	if options.apikey == nil {
		options.apikey = func() *apikey.APIKey {
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

func (o *Options) APIKey() *apikey.APIKey {
	return o.apikey()
}

func (o *Options) Manager() *manager.Manager {
	return o.manager
}

func (o *Options) NextURL() string {
	return o.nextURL()
}
