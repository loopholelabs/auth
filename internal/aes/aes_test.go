//SPDX-License-Identifier: Apache-2.0

package aes

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

type T struct {
	s string
}

func (t *T) J() {
	t.s = "TEST"
}

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

func TestDecrypt_InvalidNonceSize(t *testing.T) {
	key := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	identifier := []byte("test")

	// Content shorter than nonce size
	_, err := Decrypt(key, identifier, "short")
	require.ErrorIs(t, err, ErrInvalidNonceSize)
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	key := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	identifier := []byte("test")

	// Invalid base64 that's long enough to not trigger nonce size error
	_, err := Decrypt(key, identifier, "!!!invalid base64 content that is long enough!!!")
	require.Error(t, err)
}

func TestDecrypt_InvalidIdentifierLength(t *testing.T) {
	key := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	identifier := []byte("test")

	// Encrypt with empty content so decrypted content is shorter than identifier
	encrypted, err := Encrypt(key, []byte{}, []byte{})
	require.NoError(t, err)

	// Try to decrypt expecting a longer identifier
	_, err = Decrypt(key, identifier, encrypted)
	require.ErrorIs(t, err, ErrInvalidContent)
}

func TestDecrypt_InvalidIdentifierMatch(t *testing.T) {
	key := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	identifier := []byte("test")
	content := []byte("content")

	// Encrypt with one identifier
	encrypted, err := Encrypt(key, identifier, content)
	require.NoError(t, err)

	// Try to decrypt with different identifier
	_, err = Decrypt(key, []byte("diff"), encrypted)
	require.ErrorIs(t, err, ErrInvalidContent)
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	key := [32]byte([]byte("0123456789abcdef0123456789abcdef"))
	identifier := []byte("test")

	// Create invalid ciphertext with valid base64 encoding
	// This should have enough bytes to pass nonce size check but fail GCM decryption
	invalidCiphertext := base64.URLEncoding.EncodeToString(make([]byte, 32))

	_, err := Decrypt(key, identifier, invalidCiphertext)
	require.ErrorIs(t, err, ErrInvalidContent)
}
