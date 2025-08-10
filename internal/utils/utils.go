//SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
	"unsafe"

	"github.com/gofiber/fiber/v2"
)

var (
	ErrInvalidPKCS8PrivateKey = errors.New("invalid PKCS8 private key")
)

const (
	letterBytes       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	base32LetterBytes = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var (
	maxLetterBytes       = big.NewInt(int64(len(letterBytes)))
	maxBase32LetterBytes = big.NewInt(int64(len(base32LetterBytes)))
)

// RandomBytes generates a random byte slice of length n
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		num, _ := rand.Int(rand.Reader, maxLetterBytes)
		b[i] = letterBytes[num.Int64()]
	}
	return b
}

// RandomBase32Bytes generates a random byte slice length n of base32 characters
func RandomBase32Bytes(length int) []byte {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		num, _ := rand.Int(rand.Reader, maxBase32LetterBytes)
		b[i] = base32LetterBytes[num.Int64()]
	}
	return b
}

// RandomString generates a random string of length n
func RandomString(n int) string {
	b := RandomBytes(n)
	return *(*string)(unsafe.Pointer(&b))
}

// RandomBase32String generates a random base32 string of length n
func RandomBase32String(n int) string {
	b := RandomBase32Bytes(n)
	return *(*string)(unsafe.Pointer(&b))
}

// ConstantTimeCompareBytes compares two byte slices in constant time
func ConstantTimeCompareBytes(a []byte, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// DefaultFiberApp returns a new fiber app with sensible defaults
func DefaultFiberApp() *fiber.App {
	return fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ReadTimeout:           time.Second * 10,
		WriteTimeout:          time.Second * 10,
		IdleTimeout:           time.Second * 10,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
	})
}

func EncodeED25519PrivateKey(privateKey ed25519.PrivateKey) []byte {
	marshalled, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalled})
}

func DecodeED25519PrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, ErrInvalidPKCS8PrivateKey
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if privateKey, ok := key.(ed25519.PrivateKey); ok {
		return privateKey, nil
	}
	return nil, ErrInvalidPKCS8PrivateKey
}

func GenericZero[T any]() T {
	var zero T
	return zero
}
