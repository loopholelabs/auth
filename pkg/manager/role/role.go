//SPDX-License-Identifier: Apache-2.0

package role

type Role uint32

const (
	OwnerRole Role = iota
	AdminRole
	MemberRole
	ViewerRole
)

func (r Role) String() string {
	switch r {
	case OwnerRole:
		return "owner"
	case AdminRole:
		return "admin"
	case MemberRole:
		return "member"
	case ViewerRole:
		return "viewer"
	default:
		return "unknown"
	}
}
