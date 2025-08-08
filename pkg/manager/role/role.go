//SPDX-License-Identifier: Apache-2.0

package role

type Role string

const (
	OwnerRole  Role = "owner"
	AdminRole  Role = "admin"
	MemberRole Role = "member"
	ViewerRole Role = "viewer"
)

func (r Role) String() string {
	return string(r)
}
