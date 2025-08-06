//SPDX-License-Identifier: Apache-2.0

package utils //nolint:revive

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"time"
	"unsafe"

	"github.com/gofiber/fiber/v2"
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
