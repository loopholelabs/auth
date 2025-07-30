//SPDX-License-Identifier: Apache-2.0

package storage

// Credential is the common interface that can be used to interact with
// the various Credential types
type Credential interface {
	ImmutableData() CommonImmutableData
	MutableData() CommonMutableData
}
