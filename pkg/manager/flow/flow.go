//SPDX-License-Identifier: Apache-2.0

package flow

type Provider uint32

const (
	GithubProvider = iota
	GoogleProvider
	MagicProvider
)

type Data struct {
	ProviderIdentifier string
	Name               string
	PrimaryEmail       string
	VerifiedEmails     []string
	NextURL            string
	DeviceIdentifier   string
	UserIdentifier     string
}
