//SPDX-License-Identifier: Apache-2.0

package manager

import "time"

type OrganizationInfo struct {
	Identifier string `json:"identifier"`
	Role       string `json:"role"`
}

type UserInfo struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}

type Session struct {
	Identifier       string           `json:"identifier"`
	OrganizationInfo OrganizationInfo `json:"organization_info"`
	UserInfo         UserInfo         `json:"user_info"`
	Generation       uint32           `json:"generation"`
	ExpiresAt        time.Time        `json:"expires_at"`
}
