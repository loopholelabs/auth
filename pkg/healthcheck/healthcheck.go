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

package healthcheck

import (
	"github.com/AppsFlyer/go-sundheit"
)

type Noop struct{}

func NewNoop() *Noop {
	return new(Noop)
}

func (h *Noop) RegisterCheck(_ gosundheit.Check, _ ...gosundheit.CheckOption) error {
	return nil
}
func (h *Noop) Deregister(_ string) {}
func (h *Noop) Results() (map[string]gosundheit.Result, bool) {
	return nil, true
}
func (h *Noop) IsHealthy() bool { return true }
func (h *Noop) DeregisterAll()  {}
