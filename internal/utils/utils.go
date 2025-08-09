//SPDX-License-Identifier: Apache-2.0

package utils //nolint:revive

import (
	"crypto/ecdsa"
	"crypto/rand"
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
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	maxLetterBytes = big.NewInt(int64(len(letterBytes)))
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

// RandomString generates a random string of length n
func RandomString(n int) string {
	b := RandomBytes(n)
	return *(*string)(unsafe.Pointer(&b))
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

func EncodeECDSAPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	marshalled, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalled})
}

func DecodeECDSAPrivateKey(encoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if privateKey, ok := key.(*ecdsa.PrivateKey); ok {
		return privateKey, nil
	}
	return nil, ErrInvalidPKCS8PrivateKey
}
