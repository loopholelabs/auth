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

package options

import (
	"github.com/loopholelabs/auth/pkg/provider/github"
	"github.com/loopholelabs/auth/pkg/session"
)

type Github func() *github.Github

type Modifier func(*Options)

func WithGithub(github Github) Modifier {
	return func(options *Options) {
		options.github = github
	}
}

type Options struct {
	github  Github
	manager *session.Manager
	nextURL string
}

func New(manager *session.Manager, nextURL string, modifiers ...Modifier) *Options {
	options := &Options{
		manager: manager,
		nextURL: nextURL,
	}

	for _, modifier := range modifiers {
		modifier(options)
	}

	return options
}

func (o *Options) Github() *github.Github {
	return o.github()
}

func (o *Options) Manager() *session.Manager {
	return o.manager
}

func (o *Options) NextURL() string {
	return o.nextURL
}
