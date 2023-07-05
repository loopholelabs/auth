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
	"github.com/loopholelabs/auth/internal/ent/deviceflow"
)

// DeviceFlow is the model entity for the DeviceFlow schema.
type DeviceFlow struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// LastPoll holds the value of the "last_poll" field.
	LastPoll time.Time `json:"last_poll,omitempty"`
	// Identifier holds the value of the "identifier" field.
	Identifier string `json:"identifier,omitempty"`
	// DeviceCode holds the value of the "device_code" field.
	DeviceCode string `json:"device_code,omitempty"`
	// UserCode holds the value of the "user_code" field.
	UserCode string `json:"user_code,omitempty"`
	// Session holds the value of the "session" field.
	Session string `json:"session,omitempty"`
	// ExpiresAt holds the value of the "expires_at" field.
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*DeviceFlow) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case deviceflow.FieldID:
			values[i] = new(sql.NullInt64)
		case deviceflow.FieldIdentifier, deviceflow.FieldDeviceCode, deviceflow.FieldUserCode, deviceflow.FieldSession:
			values[i] = new(sql.NullString)
		case deviceflow.FieldCreatedAt, deviceflow.FieldLastPoll, deviceflow.FieldExpiresAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the DeviceFlow fields.
func (df *DeviceFlow) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case deviceflow.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			df.ID = int(value.Int64)
		case deviceflow.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				df.CreatedAt = value.Time
			}
		case deviceflow.FieldLastPoll:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field last_poll", values[i])
			} else if value.Valid {
				df.LastPoll = value.Time
			}
		case deviceflow.FieldIdentifier:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field identifier", values[i])
			} else if value.Valid {
				df.Identifier = value.String
			}
		case deviceflow.FieldDeviceCode:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field device_code", values[i])
			} else if value.Valid {
				df.DeviceCode = value.String
			}
		case deviceflow.FieldUserCode:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field user_code", values[i])
			} else if value.Valid {
				df.UserCode = value.String
			}
		case deviceflow.FieldSession:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field session", values[i])
			} else if value.Valid {
				df.Session = value.String
			}
		case deviceflow.FieldExpiresAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field expires_at", values[i])
			} else if value.Valid {
				df.ExpiresAt = value.Time
			}
		default:
			df.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the DeviceFlow.
// This includes values selected through modifiers, order, etc.
func (df *DeviceFlow) Value(name string) (ent.Value, error) {
	return df.selectValues.Get(name)
}

// Update returns a builder for updating this DeviceFlow.
// Note that you need to call DeviceFlow.Unwrap() before calling this method if this DeviceFlow
// was returned from a transaction, and the transaction was committed or rolled back.
func (df *DeviceFlow) Update() *DeviceFlowUpdateOne {
	return NewDeviceFlowClient(df.config).UpdateOne(df)
}

// Unwrap unwraps the DeviceFlow entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (df *DeviceFlow) Unwrap() *DeviceFlow {
	_tx, ok := df.config.driver.(*txDriver)
	if !ok {
		panic("ent: DeviceFlow is not a transactional entity")
	}
	df.config.driver = _tx.drv
	return df
}

// String implements the fmt.Stringer.
func (df *DeviceFlow) String() string {
	var builder strings.Builder
	builder.WriteString("DeviceFlow(")
	builder.WriteString(fmt.Sprintf("id=%v, ", df.ID))
	builder.WriteString("created_at=")
	builder.WriteString(df.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("last_poll=")
	builder.WriteString(df.LastPoll.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("identifier=")
	builder.WriteString(df.Identifier)
	builder.WriteString(", ")
	builder.WriteString("device_code=")
	builder.WriteString(df.DeviceCode)
	builder.WriteString(", ")
	builder.WriteString("user_code=")
	builder.WriteString(df.UserCode)
	builder.WriteString(", ")
	builder.WriteString("session=")
	builder.WriteString(df.Session)
	builder.WriteString(", ")
	builder.WriteString("expires_at=")
	builder.WriteString(df.ExpiresAt.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// DeviceFlows is a parsable slice of DeviceFlow.
type DeviceFlows []*DeviceFlow
