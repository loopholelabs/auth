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

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"time"
)

// MagicFlow holds the schema definition for the Flow entity.
type MagicFlow struct {
	ent.Schema
}

// Fields of the MagicFlow.
func (MagicFlow) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").Immutable().Default(time.Now),
		field.String("identifier").Unique().Immutable().NotEmpty(),
		field.String("email").Unique().Immutable().NotEmpty(),
		field.String("ip_address").Immutable().NotEmpty(),
		field.String("secret").Immutable().NotEmpty(),
		field.String("next_url").Immutable().NotEmpty(),
		field.String("organization").Immutable().Optional(),
		field.String("device_identifier").Immutable().Optional(),
	}
}

// Edges of the MagicFlow.
func (MagicFlow) Edges() []ent.Edge {
	return nil
}
