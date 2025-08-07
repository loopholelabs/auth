//SPDX-License-Identifier: Apache-2.0

package flow

type Provider uint32

const (
	GithubProvider = iota
	GoogleProvider
	MagicProvider
)

func (p Provider) String() string {
	switch p {
	case GithubProvider:
		return "GITHUB"
	case GoogleProvider:
		return "GOOGLE"
	case MagicProvider:
		return "MAGIC"
	default:
		return "UNKNOWN"
	}
}

type Data struct {
	ProviderIdentifier string
	Name               string
	PrimaryEmail       string
	VerifiedEmails     []string
	NextURL            string
	DeviceIdentifier   string
	UserIdentifier     string
}
