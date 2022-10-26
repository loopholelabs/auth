// Code generated by ent, DO NOT EDIT.

package ent

import (
	"time"

	"github.com/loopholelabs/auth/pkg/storage/default/ent/apikey"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/schema"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/servicekey"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/user"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	apikeyFields := schema.APIKey{}.Fields()
	_ = apikeyFields
	// apikeyDescCreatedAt is the schema descriptor for created_at field.
	apikeyDescCreatedAt := apikeyFields[0].Descriptor()
	// apikey.DefaultCreatedAt holds the default value on creation for the created_at field.
	apikey.DefaultCreatedAt = apikeyDescCreatedAt.Default.(func() int64)
	// apikeyDescValue is the schema descriptor for value field.
	apikeyDescValue := apikeyFields[1].Descriptor()
	// apikey.ValueValidator is a validator for the "value" field. It is called by the builders before save.
	apikey.ValueValidator = apikeyDescValue.Validators[0].(func(string) error)
	servicekeyFields := schema.ServiceKey{}.Fields()
	_ = servicekeyFields
	// servicekeyDescCreatedAt is the schema descriptor for created_at field.
	servicekeyDescCreatedAt := servicekeyFields[0].Descriptor()
	// servicekey.DefaultCreatedAt holds the default value on creation for the created_at field.
	servicekey.DefaultCreatedAt = servicekeyDescCreatedAt.Default.(func() int64)
	// servicekeyDescValue is the schema descriptor for value field.
	servicekeyDescValue := servicekeyFields[1].Descriptor()
	// servicekey.ValueValidator is a validator for the "value" field. It is called by the builders before save.
	servicekey.ValueValidator = servicekeyDescValue.Validators[0].(func(string) error)
	// servicekeyDescResource is the schema descriptor for resource field.
	servicekeyDescResource := servicekeyFields[3].Descriptor()
	// servicekey.DefaultResource holds the default value on creation for the resource field.
	servicekey.DefaultResource = servicekeyDescResource.Default.(string)
	// servicekeyDescNumUsed is the schema descriptor for num_used field.
	servicekeyDescNumUsed := servicekeyFields[4].Descriptor()
	// servicekey.DefaultNumUsed holds the default value on creation for the num_used field.
	servicekey.DefaultNumUsed = servicekeyDescNumUsed.Default.(int64)
	// servicekeyDescMaxUses is the schema descriptor for max_uses field.
	servicekeyDescMaxUses := servicekeyFields[5].Descriptor()
	// servicekey.DefaultMaxUses holds the default value on creation for the max_uses field.
	servicekey.DefaultMaxUses = servicekeyDescMaxUses.Default.(int64)
	// servicekeyDescExpires is the schema descriptor for expires field.
	servicekeyDescExpires := servicekeyFields[6].Descriptor()
	// servicekey.DefaultExpires holds the default value on creation for the expires field.
	servicekey.DefaultExpires = servicekeyDescExpires.Default.(int64)
	userFields := schema.User{}.Fields()
	_ = userFields
	// userDescUsername is the schema descriptor for username field.
	userDescUsername := userFields[0].Descriptor()
	// user.DefaultUsername holds the default value on creation for the username field.
	user.DefaultUsername = userDescUsername.Default.(string)
	// userDescCreatedAt is the schema descriptor for created_at field.
	userDescCreatedAt := userFields[1].Descriptor()
	// user.DefaultCreatedAt holds the default value on creation for the created_at field.
	user.DefaultCreatedAt = userDescCreatedAt.Default.(func() time.Time)
}
