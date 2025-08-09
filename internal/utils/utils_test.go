//SPDX-License-Identifier: Apache-2.0

package utils //nolint:revive

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestED25519PrivateKeyEncodeDecode(t *testing.T) {
	t.Run("ValidEncodeDecode", func(t *testing.T) {
		// Generate a new ED25519 private key
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Encode the private key
		encoded := EncodeED25519PrivateKey(privateKey)
		require.NotNil(t, encoded)
		require.NotEmpty(t, encoded)

		// Decode the private key
		decoded, err := DecodeED25519PrivateKey(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		// Verify the decoded key matches the original
		assert.Equal(t, privateKey, decoded)
	})

	t.Run("MultipleKeysEncodeDecode", func(t *testing.T) {
		// Test with multiple keys to ensure no cross-contamination
		for i := 0; i < 5; i++ {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			encoded := EncodeED25519PrivateKey(privateKey)
			decoded, err := DecodeED25519PrivateKey(encoded)
			require.NoError(t, err)
			assert.Equal(t, privateKey, decoded)
		}
	})

	t.Run("InvalidPEMBlock", func(t *testing.T) {
		// Test with invalid PEM data
		invalidPEM := []byte("not a valid PEM block")
		decoded, err := DecodeED25519PrivateKey(invalidPEM)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPKCS8PrivateKey)
		assert.Nil(t, decoded)
	})

	t.Run("EmptyInput", func(t *testing.T) {
		// Test with empty input
		decoded, err := DecodeED25519PrivateKey([]byte{})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPKCS8PrivateKey)
		assert.Nil(t, decoded)
	})

	t.Run("ValidPEMButInvalidKey", func(t *testing.T) {
		// Test with valid PEM block but invalid key data
		invalidKeyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----`)
		decoded, err := DecodeED25519PrivateKey(invalidKeyPEM)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPKCS8PrivateKey)
		assert.Nil(t, decoded)
	})

	t.Run("CorruptedPEMData", func(t *testing.T) {
		// Generate a valid key first
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Encode it
		encoded := EncodeED25519PrivateKey(privateKey)

		// Corrupt the PEM data by modifying bytes in the base64 content
		corrupted := make([]byte, len(encoded))
		copy(corrupted, encoded)
		// Find the base64 content between headers and corrupt it
		startMarker := []byte("-----BEGIN PRIVATE KEY-----")
		endMarker := []byte("-----END PRIVATE KEY-----")
		startIdx := len(startMarker) + 1 // +1 for newline
		endIdx := len(corrupted) - len(endMarker) - 1

		// Corrupt multiple bytes in the base64 content
		if startIdx < endIdx {
			for i := startIdx + 10; i < startIdx+30 && i < endIdx; i++ {
				if corrupted[i] != '\n' {
					corrupted[i] = '!' // Use an invalid base64 character
				}
			}
		}

		decoded, err := DecodeED25519PrivateKey(corrupted)
		assert.Error(t, err)
		assert.Nil(t, decoded)
	})

	t.Run("WrongPEMType", func(t *testing.T) {
		// Test with a different PEM type
		wrongTypePEM := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
-----END RSA PRIVATE KEY-----`)
		decoded, err := DecodeED25519PrivateKey(wrongTypePEM)
		assert.Error(t, err)
		assert.Nil(t, decoded)
	})
}
