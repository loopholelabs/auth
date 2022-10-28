package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/pkg/utils"
)

// APIKey holds the schema definition for the APIKey entity.
type APIKey struct {
	ent.Schema
}

// Fields of the APIKey.
func (APIKey) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("created_at").Immutable().DefaultFunc(utils.TimeInt64Now),
		field.String("name").NotEmpty().Immutable(),
		field.String("value").Unique().NotEmpty().Immutable(),
		field.Bytes("secret").Immutable(),
	}
}

// Edges of the APIKey.
func (APIKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).Ref("apikeys").Unique(),
	}
}
