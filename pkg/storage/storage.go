package storage

import (
	dexStorage "github.com/dexidp/dex/storage"
)

type ServiceKeyValid func(key *ServiceKey) error
type ServiceKeyUpdate func(key *ServiceKey)

type APIKey struct {
	Created int64
	ID      string
	Secret  []byte
	User    string
}

type ServiceKey struct {
	Created  int64
	ID       string
	Secret   []byte
	User     string
	Resource string
	NumUsed  int64
	MaxUses  int64
	Expires  int64
}

type Storage interface {
	dexStorage.Storage

	UserExists(id string) (bool, error)

	GetAPIKey(id string) (*APIKey, error)
	CreateAPIKey(key *APIKey) error

	GetServiceKey(id string, valid ServiceKeyValid, update ServiceKeyUpdate) (*ServiceKey, error)
	CreateServiceKey(key *ServiceKey) error
}
