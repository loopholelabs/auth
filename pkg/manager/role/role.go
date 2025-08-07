//SPDX-License-Identifier: Apache-2.0

package role

type Role uint32

const (
	OwnerRole Role = iota
)

func (r Role) String() string {
	switch r {
	case OwnerRole:
		return "OWNER"
	default:
		return "UNKNOWN"
	}
}
