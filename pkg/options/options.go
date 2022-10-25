package options

import (
	"errors"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/web"
	"github.com/loopholelabs/auth/pkg/storage"
	"github.com/loopholelabs/auth/pkg/token/identity"
)

var (
	InvalidIssuerError        = errors.New("invalid issuer")
	InvalidAllowsOriginsError = errors.New("invalid allowed origins")
	InvalidStorageError       = errors.New("invalid storage")
	InvalidLoggerError        = errors.New("invalid logger")
	InvalidNewUserError       = errors.New("invalid new user callback")
)

type Options struct {
	Issuer         string
	AllowedOrigins []string

	Storage   storage.Storage
	Logger    log.Logger
	WebConfig *server.WebConfig

	Enabled      func() bool
	Registration func() bool
	NewUser      func(claims *identity.IDToken) error
}

func (o *Options) Validate() error {
	if o.Issuer == "" {
		return InvalidIssuerError
	}

	if len(o.AllowedOrigins) == 0 {
		return InvalidAllowsOriginsError
	}

	if o.Storage == nil {
		return InvalidStorageError
	}

	if o.Logger == nil {
		return InvalidLoggerError
	}

	if o.WebConfig == nil {
		o.WebConfig = &server.WebConfig{
			WebFS: web.FS(),
		}
	}

	if o.Enabled == nil {
		o.Enabled = func() bool { return true }
	}

	if o.Registration == nil {
		o.Registration = func() bool { return true }
	}

	if o.NewUser == nil {
		return InvalidNewUserError
	}

	return nil
}
