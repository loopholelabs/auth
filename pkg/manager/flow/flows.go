//SPDX-License-Identifier: Apache-2.0

package flow

type Flow struct {
	Identifier       string
	Name             string
	PrimaryEmail     string
	VerifiedEmails   []string
	NextURL          string
	DeviceIdentifier string
	UserIdentifier   string
}
