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

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// DeviceFlowsColumns holds the columns for the "device_flows" table.
	DeviceFlowsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "last_poll", Type: field.TypeTime},
		{Name: "identifier", Type: field.TypeString, Unique: true},
		{Name: "device_code", Type: field.TypeString, Unique: true},
		{Name: "user_code", Type: field.TypeString, Unique: true},
		{Name: "session", Type: field.TypeString, Unique: true, Nullable: true},
		{Name: "expires_at", Type: field.TypeTime, Nullable: true},
	}
	// DeviceFlowsTable holds the schema information for the "device_flows" table.
	DeviceFlowsTable = &schema.Table{
		Name:       "device_flows",
		Columns:    DeviceFlowsColumns,
		PrimaryKey: []*schema.Column{DeviceFlowsColumns[0]},
	}
	// GithubFlowsColumns holds the columns for the "github_flows" table.
	GithubFlowsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "state", Type: field.TypeString, Unique: true},
		{Name: "verifier", Type: field.TypeString, Unique: true},
		{Name: "challenge", Type: field.TypeString, Unique: true},
		{Name: "next_url", Type: field.TypeString},
		{Name: "organization", Type: field.TypeString, Nullable: true},
		{Name: "device_identifier", Type: field.TypeString, Unique: true, Nullable: true},
	}
	// GithubFlowsTable holds the schema information for the "github_flows" table.
	GithubFlowsTable = &schema.Table{
		Name:       "github_flows",
		Columns:    GithubFlowsColumns,
		PrimaryKey: []*schema.Column{GithubFlowsColumns[0]},
	}
	// GoogleFlowsColumns holds the columns for the "google_flows" table.
	GoogleFlowsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "state", Type: field.TypeString, Unique: true},
		{Name: "verifier", Type: field.TypeString, Unique: true},
		{Name: "challenge", Type: field.TypeString, Unique: true},
		{Name: "next_url", Type: field.TypeString},
		{Name: "organization", Type: field.TypeString, Nullable: true},
		{Name: "device_identifier", Type: field.TypeString, Unique: true, Nullable: true},
	}
	// GoogleFlowsTable holds the schema information for the "google_flows" table.
	GoogleFlowsTable = &schema.Table{
		Name:       "google_flows",
		Columns:    GoogleFlowsColumns,
		PrimaryKey: []*schema.Column{GoogleFlowsColumns[0]},
	}
	// MagicFlowsColumns holds the columns for the "magic_flows" table.
	MagicFlowsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "email", Type: field.TypeString, Unique: true},
		{Name: "ip_address", Type: field.TypeString},
		{Name: "secret", Type: field.TypeString},
		{Name: "next_url", Type: field.TypeString},
		{Name: "organization", Type: field.TypeString, Nullable: true},
		{Name: "device_identifier", Type: field.TypeString, Unique: true, Nullable: true},
	}
	// MagicFlowsTable holds the schema information for the "magic_flows" table.
	MagicFlowsTable = &schema.Table{
		Name:       "magic_flows",
		Columns:    MagicFlowsColumns,
		PrimaryKey: []*schema.Column{MagicFlowsColumns[0]},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		DeviceFlowsTable,
		GithubFlowsTable,
		GoogleFlowsTable,
		MagicFlowsTable,
	}
)

func init() {
}
