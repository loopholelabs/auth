// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/loopholelabs/auth/internal/ent/githubflow"
)

// GithubFlow is the model entity for the GithubFlow schema.
type GithubFlow struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// State holds the value of the "state" field.
	State string `json:"state,omitempty"`
	// Verifier holds the value of the "verifier" field.
	Verifier string `json:"verifier,omitempty"`
	// Challenge holds the value of the "challenge" field.
	Challenge string `json:"challenge,omitempty"`
	// NextURL holds the value of the "next_url" field.
	NextURL string `json:"next_url,omitempty"`
	// Organization holds the value of the "organization" field.
	Organization string `json:"organization,omitempty"`
	// DeviceIdentifier holds the value of the "device_identifier" field.
	DeviceIdentifier string `json:"device_identifier,omitempty"`
}

// scanValues returns the types for scanning values from sql.Rows.
func (*GithubFlow) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case githubflow.FieldID:
			values[i] = new(sql.NullInt64)
		case githubflow.FieldState, githubflow.FieldVerifier, githubflow.FieldChallenge, githubflow.FieldNextURL, githubflow.FieldOrganization, githubflow.FieldDeviceIdentifier:
			values[i] = new(sql.NullString)
		case githubflow.FieldCreatedAt:
			values[i] = new(sql.NullTime)
		default:
			return nil, fmt.Errorf("unexpected column %q for type GithubFlow", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the GithubFlow fields.
func (gf *GithubFlow) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case githubflow.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			gf.ID = int(value.Int64)
		case githubflow.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				gf.CreatedAt = value.Time
			}
		case githubflow.FieldState:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field state", values[i])
			} else if value.Valid {
				gf.State = value.String
			}
		case githubflow.FieldVerifier:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field verifier", values[i])
			} else if value.Valid {
				gf.Verifier = value.String
			}
		case githubflow.FieldChallenge:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field challenge", values[i])
			} else if value.Valid {
				gf.Challenge = value.String
			}
		case githubflow.FieldNextURL:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field next_url", values[i])
			} else if value.Valid {
				gf.NextURL = value.String
			}
		case githubflow.FieldOrganization:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field organization", values[i])
			} else if value.Valid {
				gf.Organization = value.String
			}
		case githubflow.FieldDeviceIdentifier:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field device_identifier", values[i])
			} else if value.Valid {
				gf.DeviceIdentifier = value.String
			}
		}
	}
	return nil
}

// Update returns a builder for updating this GithubFlow.
// Note that you need to call GithubFlow.Unwrap() before calling this method if this GithubFlow
// was returned from a transaction, and the transaction was committed or rolled back.
func (gf *GithubFlow) Update() *GithubFlowUpdateOne {
	return (&GithubFlowClient{config: gf.config}).UpdateOne(gf)
}

// Unwrap unwraps the GithubFlow entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (gf *GithubFlow) Unwrap() *GithubFlow {
	_tx, ok := gf.config.driver.(*txDriver)
	if !ok {
		panic("ent: GithubFlow is not a transactional entity")
	}
	gf.config.driver = _tx.drv
	return gf
}

// String implements the fmt.Stringer.
func (gf *GithubFlow) String() string {
	var builder strings.Builder
	builder.WriteString("GithubFlow(")
	builder.WriteString(fmt.Sprintf("id=%v, ", gf.ID))
	builder.WriteString("created_at=")
	builder.WriteString(gf.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("state=")
	builder.WriteString(gf.State)
	builder.WriteString(", ")
	builder.WriteString("verifier=")
	builder.WriteString(gf.Verifier)
	builder.WriteString(", ")
	builder.WriteString("challenge=")
	builder.WriteString(gf.Challenge)
	builder.WriteString(", ")
	builder.WriteString("next_url=")
	builder.WriteString(gf.NextURL)
	builder.WriteString(", ")
	builder.WriteString("organization=")
	builder.WriteString(gf.Organization)
	builder.WriteString(", ")
	builder.WriteString("device_identifier=")
	builder.WriteString(gf.DeviceIdentifier)
	builder.WriteByte(')')
	return builder.String()
}

// GithubFlows is a parsable slice of GithubFlow.
type GithubFlows []*GithubFlow

func (gf GithubFlows) config(cfg config) {
	for _i := range gf {
		gf[_i].config = cfg
	}
}
