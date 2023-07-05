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
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/loopholelabs/auth/internal/ent/magicflow"
)

// MagicFlow is the model entity for the MagicFlow schema.
type MagicFlow struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// Identifier holds the value of the "identifier" field.
	Identifier string `json:"identifier,omitempty"`
	// Email holds the value of the "email" field.
	Email string `json:"email,omitempty"`
	// IPAddress holds the value of the "ip_address" field.
	IPAddress string `json:"ip_address,omitempty"`
	// Secret holds the value of the "secret" field.
	Secret string `json:"secret,omitempty"`
	// NextURL holds the value of the "next_url" field.
	NextURL string `json:"next_url,omitempty"`
	// Organization holds the value of the "organization" field.
	Organization string `json:"organization,omitempty"`
	// DeviceIdentifier holds the value of the "device_identifier" field.
	DeviceIdentifier string `json:"device_identifier,omitempty"`
	selectValues     sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*MagicFlow) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case magicflow.FieldID:
			values[i] = new(sql.NullInt64)
		case magicflow.FieldIdentifier, magicflow.FieldEmail, magicflow.FieldIPAddress, magicflow.FieldSecret, magicflow.FieldNextURL, magicflow.FieldOrganization, magicflow.FieldDeviceIdentifier:
			values[i] = new(sql.NullString)
		case magicflow.FieldCreatedAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the MagicFlow fields.
func (mf *MagicFlow) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case magicflow.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			mf.ID = int(value.Int64)
		case magicflow.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				mf.CreatedAt = value.Time
			}
		case magicflow.FieldIdentifier:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field identifier", values[i])
			} else if value.Valid {
				mf.Identifier = value.String
			}
		case magicflow.FieldEmail:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field email", values[i])
			} else if value.Valid {
				mf.Email = value.String
			}
		case magicflow.FieldIPAddress:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field ip_address", values[i])
			} else if value.Valid {
				mf.IPAddress = value.String
			}
		case magicflow.FieldSecret:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field secret", values[i])
			} else if value.Valid {
				mf.Secret = value.String
			}
		case magicflow.FieldNextURL:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field next_url", values[i])
			} else if value.Valid {
				mf.NextURL = value.String
			}
		case magicflow.FieldOrganization:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field organization", values[i])
			} else if value.Valid {
				mf.Organization = value.String
			}
		case magicflow.FieldDeviceIdentifier:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field device_identifier", values[i])
			} else if value.Valid {
				mf.DeviceIdentifier = value.String
			}
		default:
			mf.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the MagicFlow.
// This includes values selected through modifiers, order, etc.
func (mf *MagicFlow) Value(name string) (ent.Value, error) {
	return mf.selectValues.Get(name)
}

// Update returns a builder for updating this MagicFlow.
// Note that you need to call MagicFlow.Unwrap() before calling this method if this MagicFlow
// was returned from a transaction, and the transaction was committed or rolled back.
func (mf *MagicFlow) Update() *MagicFlowUpdateOne {
	return NewMagicFlowClient(mf.config).UpdateOne(mf)
}

// Unwrap unwraps the MagicFlow entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (mf *MagicFlow) Unwrap() *MagicFlow {
	_tx, ok := mf.config.driver.(*txDriver)
	if !ok {
		panic("ent: MagicFlow is not a transactional entity")
	}
	mf.config.driver = _tx.drv
	return mf
}

// String implements the fmt.Stringer.
func (mf *MagicFlow) String() string {
	var builder strings.Builder
	builder.WriteString("MagicFlow(")
	builder.WriteString(fmt.Sprintf("id=%v, ", mf.ID))
	builder.WriteString("created_at=")
	builder.WriteString(mf.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("identifier=")
	builder.WriteString(mf.Identifier)
	builder.WriteString(", ")
	builder.WriteString("email=")
	builder.WriteString(mf.Email)
	builder.WriteString(", ")
	builder.WriteString("ip_address=")
	builder.WriteString(mf.IPAddress)
	builder.WriteString(", ")
	builder.WriteString("secret=")
	builder.WriteString(mf.Secret)
	builder.WriteString(", ")
	builder.WriteString("next_url=")
	builder.WriteString(mf.NextURL)
	builder.WriteString(", ")
	builder.WriteString("organization=")
	builder.WriteString(mf.Organization)
	builder.WriteString(", ")
	builder.WriteString("device_identifier=")
	builder.WriteString(mf.DeviceIdentifier)
	builder.WriteByte(')')
	return builder.String()
}

// MagicFlows is a parsable slice of MagicFlow.
type MagicFlows []*MagicFlow
