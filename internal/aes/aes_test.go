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

package aes

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAES(t *testing.T) {
	key := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	identifier := []byte("test")
	content := []byte("content")

	encrypted, err := Encrypt(key, identifier, content)
	require.NoError(t, err)

	decrypted, err := Decrypt(key, identifier, encrypted)
	require.NoError(t, err)
	require.Equal(t, content, decrypted)

	_, err = Decrypt([32]byte([]byte("0123456789abcdef0123456789abcdee")), identifier, encrypted)
	require.ErrorIs(t, err, ErrInvalidContent)
}
