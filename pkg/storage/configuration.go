//SPDX-License-Identifier: Apache-2.0

package storage

import "context"

// Configuration represents the Configuration for Authentication
type Configuration struct {
}

// ConfigurationReadProvider is the read-only storage interface for Configurations
type ConfigurationReadProvider interface {
	// GetConfiguration returns the Configuration
	//
	// If the Configuration does not exist, ErrNotFound is returned.
	GetConfiguration(ctx context.Context) (Configuration, error)
}

// ConfigurationWriteProvider is the write-only storage interface for Configurations
type ConfigurationWriteProvider interface {
	// SetConfiguration sets the Configuration.
	SetConfiguration(ctx context.Context, configuration Configuration) error
}

// ConfigurationProvider is the storage interface for Configurations
type ConfigurationProvider interface {
	// ConfigurationReadProvider is the read-only storage interfaces for Configurations
	ConfigurationReadProvider

	// ConfigurationWriteProvider is the write-only storage interfaces for Configurations
	ConfigurationWriteProvider
}
