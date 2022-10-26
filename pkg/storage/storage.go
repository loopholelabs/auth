package storage

import (
	dexStorage "github.com/dexidp/dex/storage"
	"github.com/loopholelabs/auth/pkg/token"
)

type ServiceKeyValid func(key *token.ServiceKey) error
type ServiceKeyUpdate func(key *token.ServiceKey)

type Storage interface {
	dexStorage.Storage

	UserExists(id string) (bool, error)

	GetAPIKey(id string) (*token.APIKey, error)
	CreateAPIKey(apiKey *token.APIKey) error

	GetServiceKey(id string, valid ServiceKeyValid, update ServiceKeyUpdate) (*token.ServiceKey, error)
	CreateServiceKey(serviceKey *token.ServiceKey) error
}
