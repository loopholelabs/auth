//SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"

	"github.com/loopholelabs/auth/pkg/manager"
	"github.com/loopholelabs/auth/pkg/validator"
)

var (
	ErrInvalidOptions = errors.New("invalid options")
)

type Options struct {
	Endpoint  string
	TLS       bool
	Manager   *manager.Manager
	Validator *validator.Validator
}

func (o Options) IsValid() bool {
	return o.Manager != nil && o.Validator != nil
}
