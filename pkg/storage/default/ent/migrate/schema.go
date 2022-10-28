// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// APIKeysColumns holds the columns for the "api_keys" table.
	APIKeysColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "created_at", Type: field.TypeInt64},
		{Name: "name", Type: field.TypeString},
		{Name: "value", Type: field.TypeString, Unique: true},
		{Name: "secret", Type: field.TypeBytes},
		{Name: "user_apikeys", Type: field.TypeInt, Nullable: true},
	}
	// APIKeysTable holds the schema information for the "api_keys" table.
	APIKeysTable = &schema.Table{
		Name:       "api_keys",
		Columns:    APIKeysColumns,
		PrimaryKey: []*schema.Column{APIKeysColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "api_keys_users_apikeys",
				Columns:    []*schema.Column{APIKeysColumns[5]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// ServiceKeysColumns holds the columns for the "service_keys" table.
	ServiceKeysColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "created_at", Type: field.TypeInt64},
		{Name: "name", Type: field.TypeString},
		{Name: "value", Type: field.TypeString, Unique: true},
		{Name: "secret", Type: field.TypeBytes},
		{Name: "resource", Type: field.TypeString, Default: ""},
		{Name: "num_used", Type: field.TypeInt64, Default: 0},
		{Name: "max_uses", Type: field.TypeInt64, Default: 0},
		{Name: "expires", Type: field.TypeInt64, Default: 0},
		{Name: "user_servicekeys", Type: field.TypeInt, Nullable: true},
	}
	// ServiceKeysTable holds the schema information for the "service_keys" table.
	ServiceKeysTable = &schema.Table{
		Name:       "service_keys",
		Columns:    ServiceKeysColumns,
		PrimaryKey: []*schema.Column{ServiceKeysColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "service_keys_users_servicekeys",
				Columns:    []*schema.Column{ServiceKeysColumns[9]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "username", Type: field.TypeString, Default: "unknown"},
		{Name: "created_at", Type: field.TypeTime},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		APIKeysTable,
		ServiceKeysTable,
		UsersTable,
	}
)

func init() {
	APIKeysTable.ForeignKeys[0].RefTable = UsersTable
	ServiceKeysTable.ForeignKeys[0].RefTable = UsersTable
}
