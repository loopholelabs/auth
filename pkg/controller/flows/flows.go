//SPDX-License-Identifier: Apache-2.0

package flows

type Flow struct {
	Identifier       string
	PrimaryEmail     string
	VerifiedEmails   []string
	NextURL          string
	DeviceIdentifier string
	UserIdentifier   string
}
