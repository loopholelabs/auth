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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var (
	ErrInvalidNonceSize = errors.New("invalid nonce size")
	ErrInvalidContent   = errors.New("invalid content")
)

func Encrypt(secretKey [32]byte, identifier []byte, content []byte) (string, error) {
	block, err := aes.NewCipher(secretKey[:])
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aesGCM.Seal(nonce, nonce, append(identifier, content...), nil)), nil
}

func Decrypt(secretKey [32]byte, identifier []byte, content string) ([]byte, error) {
	block, err := aes.NewCipher(secretKey[:])
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

	contentBytes, err := base64.URLEncoding.DecodeString(content)
	if err != nil {
		return nil, err
	}

	contentBytes, err = aesGCM.Open(nil, contentBytes[:nonceSize], contentBytes[nonceSize:], nil)
	if err != nil {
		return nil, ErrInvalidContent
	}

	if len(contentBytes) < len(identifier) {
		return nil, ErrInvalidContent
	}

	if !bytes.Equal(contentBytes[:len(identifier)], identifier) {
		return nil, ErrInvalidContent
	}

	return contentBytes[len(identifier):], nil
}
