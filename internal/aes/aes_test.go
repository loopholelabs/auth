//SPDX-License-Identifier: Apache-2.0

package aes

import (
	"testing"

	"github.com/stretchr/testify/require"
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
