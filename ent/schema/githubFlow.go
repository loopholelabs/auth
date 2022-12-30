/*
	Copyright 2022 Loophole Labs

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

// GithubFlow holds the schema definition for the Flow entity.
type GithubFlow struct {
	ent.Schema
}

// Fields of the GithubFlow.
func (GithubFlow) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").Immutable().Default(time.Now),
		field.String("state").Unique().Immutable().NotEmpty(),
		field.String("organization").Immutable().NotEmpty(),
		field.String("verifier").Unique().Immutable().NotEmpty(),
		field.String("challenge").Unique().Immutable().NotEmpty(),
	}
}

// Edges of the GithubFlow.
func (GithubFlow) Edges() []ent.Edge {
	return nil
}
