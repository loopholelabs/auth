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

package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrInvalidNonceSize = errors.New("invalid nonce size")
	ErrInvalidContent   = errors.New("invalid content")
)

func Encrypt(secretKey []byte, identifier []byte, content []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, append(identifier, content...), nil), nil
}

func Decrypt(secretKey []byte, identifier []byte, content []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()

	if len(content) < nonceSize {
		return nil, ErrInvalidNonceSize
	}

	content, err = aesGCM.Open(nil, content[:nonceSize], content[nonceSize:], nil)
	if err != nil {
		return nil, ErrInvalidContent
	}

	if len(content) < len(identifier) {
		return nil, ErrInvalidContent
	}

	if !bytes.Equal(content[:len(identifier)], identifier) {
		return nil, ErrInvalidContent
	}

	return content[len(identifier):], nil
}
