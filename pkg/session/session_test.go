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

package session

import (
	"github.com/loopholelabs/auth/pkg/kind"
	"github.com/loopholelabs/auth/pkg/provider"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSession(t *testing.T) {
	pkey := provider.Key("test-provider")
	sess := New(kind.Default, pkey, "test-userid", "test-organization")
	require.Equal(t, kind.Default, sess.Kind)
	require.Equal(t, pkey, sess.Provider)
	require.Equal(t, "test-userid", sess.UserID)
	require.Equal(t, "test-organization", sess.Organization)

	require.False(t, sess.Expired())
	require.False(t, sess.CloseToExpiry())
}
