//SPDX-License-Identifier: Apache-2.0

//nolint:revive
package user

import "time"

type IdentityInfo struct {
	Provider       string    `json:"provider" doc:"identity provider"`
	VerifiedEmails []string  `json:"verified_emails" doc:"verified emails"`
	CreatedAt      time.Time `json:"created_at" doc:"created at time"`
}

type OrganizationInfo struct {
	Name      string    `json:"name" doc:"organization name"`
	CreatedAt time.Time `json:"created_at" doc:"organization creation time"`
	Role      string    `json:"membership_role" doc:"user's role in this organization"`
	JoinedAt  time.Time `json:"joined_at" doc:"when the user joined this organization"`
}

type UserInfoResponseBody struct {
	Name                string             `json:"name" doc:"user's name"`
	Email               string             `json:"email" doc:"user's email address"`
	LastLogin           time.Time          `json:"last_login" doc:"user's last login"`
	CreatedAt           time.Time          `json:"created_at" doc:"user's creation time"`
	DefaultOrganization OrganizationInfo   `json:"default_organization" doc:"user's default organization"`
	Organizations       []OrganizationInfo `json:"organizations" doc:"user's organizations"`
	Identities          []IdentityInfo     `json:"identities" doc:"user's identities"`
}

type UserInfoResponse struct {
	Body UserInfoResponseBody
}

type UserUpdateRequest struct {
	Name  string `query:"name" required:"false" minLength:"1" maxLength:"255" doc:"user's name'"`
	Email string `query:"email" required:"false" minLength:"3" maxLength:"255" doc:"user's email'"`
}
