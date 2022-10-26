package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/pkg/utils"
)

// ServiceKey holds the schema definition for the ServiceKey entity.
type ServiceKey struct {
	ent.Schema
}

// Fields of the RefreshToken.
func (ServiceKey) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("created_at").Immutable().DefaultFunc(utils.TimeInt64Now),
		field.String("value").Unique().NotEmpty().Immutable(),
		field.Bytes("secret").Immutable(),
		field.String("resource").Default(""),
		field.Int64("num_used").Default(0),
		field.Int64("max_uses").Default(0),
		field.Int64("expires").Default(0),
	}
}

// Edges of the RefreshToken.
func (ServiceKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).Ref("servicekeys").Unique(),
	}
}
