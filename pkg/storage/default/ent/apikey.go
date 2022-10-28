// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/apikey"
	"github.com/loopholelabs/auth/pkg/storage/default/ent/user"
)

// APIKey is the model entity for the APIKey schema.
type APIKey struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt int64 `json:"created_at,omitempty"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// Value holds the value of the "value" field.
	Value string `json:"value,omitempty"`
	// Secret holds the value of the "secret" field.
	Secret []byte `json:"secret,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the APIKeyQuery when eager-loading is set.
	Edges        APIKeyEdges `json:"edges"`
	user_apikeys *int
}

// APIKeyEdges holds the relations/edges for other nodes in the graph.
type APIKeyEdges struct {
	// Owner holds the value of the owner edge.
	Owner *User `json:"owner,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// OwnerOrErr returns the Owner value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e APIKeyEdges) OwnerOrErr() (*User, error) {
	if e.loadedTypes[0] {
		if e.Owner == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: user.Label}
		}
		return e.Owner, nil
	}
	return nil, &NotLoadedError{edge: "owner"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*APIKey) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case apikey.FieldSecret:
			values[i] = new([]byte)
		case apikey.FieldID, apikey.FieldCreatedAt:
			values[i] = new(sql.NullInt64)
		case apikey.FieldName, apikey.FieldValue:
			values[i] = new(sql.NullString)
		case apikey.ForeignKeys[0]: // user_apikeys
			values[i] = new(sql.NullInt64)
		default:
			return nil, fmt.Errorf("unexpected column %q for type APIKey", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the APIKey fields.
func (ak *APIKey) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case apikey.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			ak.ID = int(value.Int64)
		case apikey.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				ak.CreatedAt = value.Int64
			}
		case apikey.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				ak.Name = value.String
			}
		case apikey.FieldValue:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field value", values[i])
			} else if value.Valid {
				ak.Value = value.String
			}
		case apikey.FieldSecret:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field secret", values[i])
			} else if value != nil {
				ak.Secret = *value
			}
		case apikey.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for edge-field user_apikeys", value)
			} else if value.Valid {
				ak.user_apikeys = new(int)
				*ak.user_apikeys = int(value.Int64)
			}
		}
	}
	return nil
}

// QueryOwner queries the "owner" edge of the APIKey entity.
func (ak *APIKey) QueryOwner() *UserQuery {
	return (&APIKeyClient{config: ak.config}).QueryOwner(ak)
}

// Update returns a builder for updating this APIKey.
// Note that you need to call APIKey.Unwrap() before calling this method if this APIKey
// was returned from a transaction, and the transaction was committed or rolled back.
func (ak *APIKey) Update() *APIKeyUpdateOne {
	return (&APIKeyClient{config: ak.config}).UpdateOne(ak)
}

// Unwrap unwraps the APIKey entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ak *APIKey) Unwrap() *APIKey {
	_tx, ok := ak.config.driver.(*txDriver)
	if !ok {
		panic("ent: APIKey is not a transactional entity")
	}
	ak.config.driver = _tx.drv
	return ak
}

// String implements the fmt.Stringer.
func (ak *APIKey) String() string {
	var builder strings.Builder
	builder.WriteString("APIKey(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ak.ID))
	builder.WriteString("created_at=")
	builder.WriteString(fmt.Sprintf("%v", ak.CreatedAt))
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(ak.Name)
	builder.WriteString(", ")
	builder.WriteString("value=")
	builder.WriteString(ak.Value)
	builder.WriteString(", ")
	builder.WriteString("secret=")
	builder.WriteString(fmt.Sprintf("%v", ak.Secret))
	builder.WriteByte(')')
	return builder.String()
}

// APIKeys is a parsable slice of APIKey.
type APIKeys []*APIKey

func (ak APIKeys) config(cfg config) {
	for _i := range ak {
		ak[_i].config = cfg
	}
}
