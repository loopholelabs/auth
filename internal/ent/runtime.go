/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Code generated by ent, DO NOT EDIT.

package ent

import (
	"time"

	"github.com/loopholelabs/auth/internal/ent/deviceflow"
	"github.com/loopholelabs/auth/internal/ent/githubflow"
	"github.com/loopholelabs/auth/internal/ent/magicflow"
	"github.com/loopholelabs/auth/internal/ent/schema"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	deviceflowFields := schema.DeviceFlow{}.Fields()
	_ = deviceflowFields
	// deviceflowDescCreatedAt is the schema descriptor for created_at field.
	deviceflowDescCreatedAt := deviceflowFields[0].Descriptor()
	// deviceflow.DefaultCreatedAt holds the default value on creation for the created_at field.
	deviceflow.DefaultCreatedAt = deviceflowDescCreatedAt.Default.(func() time.Time)
	// deviceflowDescLastPoll is the schema descriptor for last_poll field.
	deviceflowDescLastPoll := deviceflowFields[1].Descriptor()
	// deviceflow.DefaultLastPoll holds the default value on creation for the last_poll field.
	deviceflow.DefaultLastPoll = deviceflowDescLastPoll.Default.(func() time.Time)
	// deviceflowDescIdentifier is the schema descriptor for identifier field.
	deviceflowDescIdentifier := deviceflowFields[2].Descriptor()
	// deviceflow.IdentifierValidator is a validator for the "identifier" field. It is called by the builders before save.
	deviceflow.IdentifierValidator = deviceflowDescIdentifier.Validators[0].(func(string) error)
	// deviceflowDescDeviceCode is the schema descriptor for device_code field.
	deviceflowDescDeviceCode := deviceflowFields[3].Descriptor()
	// deviceflow.DeviceCodeValidator is a validator for the "device_code" field. It is called by the builders before save.
	deviceflow.DeviceCodeValidator = deviceflowDescDeviceCode.Validators[0].(func(string) error)
	// deviceflowDescUserCode is the schema descriptor for user_code field.
	deviceflowDescUserCode := deviceflowFields[4].Descriptor()
	// deviceflow.UserCodeValidator is a validator for the "user_code" field. It is called by the builders before save.
	deviceflow.UserCodeValidator = deviceflowDescUserCode.Validators[0].(func(string) error)
	githubflowFields := schema.GithubFlow{}.Fields()
	_ = githubflowFields
	// githubflowDescCreatedAt is the schema descriptor for created_at field.
	githubflowDescCreatedAt := githubflowFields[0].Descriptor()
	// githubflow.DefaultCreatedAt holds the default value on creation for the created_at field.
	githubflow.DefaultCreatedAt = githubflowDescCreatedAt.Default.(func() time.Time)
	// githubflowDescState is the schema descriptor for state field.
	githubflowDescState := githubflowFields[1].Descriptor()
	// githubflow.StateValidator is a validator for the "state" field. It is called by the builders before save.
	githubflow.StateValidator = githubflowDescState.Validators[0].(func(string) error)
	// githubflowDescVerifier is the schema descriptor for verifier field.
	githubflowDescVerifier := githubflowFields[2].Descriptor()
	// githubflow.VerifierValidator is a validator for the "verifier" field. It is called by the builders before save.
	githubflow.VerifierValidator = githubflowDescVerifier.Validators[0].(func(string) error)
	// githubflowDescChallenge is the schema descriptor for challenge field.
	githubflowDescChallenge := githubflowFields[3].Descriptor()
	// githubflow.ChallengeValidator is a validator for the "challenge" field. It is called by the builders before save.
	githubflow.ChallengeValidator = githubflowDescChallenge.Validators[0].(func(string) error)
	// githubflowDescNextURL is the schema descriptor for next_url field.
	githubflowDescNextURL := githubflowFields[4].Descriptor()
	// githubflow.NextURLValidator is a validator for the "next_url" field. It is called by the builders before save.
	githubflow.NextURLValidator = githubflowDescNextURL.Validators[0].(func(string) error)
	magicflowFields := schema.MagicFlow{}.Fields()
	_ = magicflowFields
	// magicflowDescCreatedAt is the schema descriptor for created_at field.
	magicflowDescCreatedAt := magicflowFields[0].Descriptor()
	// magicflow.DefaultCreatedAt holds the default value on creation for the created_at field.
	magicflow.DefaultCreatedAt = magicflowDescCreatedAt.Default.(func() time.Time)
	// magicflowDescEmail is the schema descriptor for email field.
	magicflowDescEmail := magicflowFields[1].Descriptor()
	// magicflow.EmailValidator is a validator for the "email" field. It is called by the builders before save.
	magicflow.EmailValidator = magicflowDescEmail.Validators[0].(func(string) error)
	// magicflowDescIPAddress is the schema descriptor for ip_address field.
	magicflowDescIPAddress := magicflowFields[2].Descriptor()
	// magicflow.IPAddressValidator is a validator for the "ip_address" field. It is called by the builders before save.
	magicflow.IPAddressValidator = magicflowDescIPAddress.Validators[0].(func(string) error)
	// magicflowDescSecret is the schema descriptor for secret field.
	magicflowDescSecret := magicflowFields[3].Descriptor()
	// magicflow.SecretValidator is a validator for the "secret" field. It is called by the builders before save.
	magicflow.SecretValidator = magicflowDescSecret.Validators[0].(func(string) error)
	// magicflowDescNextURL is the schema descriptor for next_url field.
	magicflowDescNextURL := magicflowFields[4].Descriptor()
	// magicflow.NextURLValidator is a validator for the "next_url" field. It is called by the builders before save.
	magicflow.NextURLValidator = magicflowDescNextURL.Validators[0].(func(string) error)
}
