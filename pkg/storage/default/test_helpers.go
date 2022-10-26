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

package database

import (
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"testing"
)

func NewTestDatabase(t *testing.T) *Default {
	d, err := New("sqlite3", ":memory:?_fk=1", logrus.New())
	require.NoError(t, err)

	return d
}
