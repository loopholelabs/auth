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

package github

import (
	"context"
	"github.com/loopholelabs/auth/ent"
	"time"
)

type Database interface {
	SetGithubFlow(ctx context.Context, state string, organization string, verifier string, challenge string) error
	GetGithubFlow(ctx context.Context, state string) (*ent.GithubFlow, error)
	DeleteGithubFlow(ctx context.Context, state string) error
	GCGithubFlow(ctx context.Context, expiry time.Duration) (int, error)
}
