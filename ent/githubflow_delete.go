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
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/ent/githubflow"
	"github.com/loopholelabs/auth/ent/predicate"
)

// GithubFlowDelete is the builder for deleting a GithubFlow entity.
type GithubFlowDelete struct {
	config
	hooks    []Hook
	mutation *GithubFlowMutation
}

// Where appends a list predicates to the GithubFlowDelete builder.
func (gfd *GithubFlowDelete) Where(ps ...predicate.GithubFlow) *GithubFlowDelete {
	gfd.mutation.Where(ps...)
	return gfd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (gfd *GithubFlowDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(gfd.hooks) == 0 {
		affected, err = gfd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*GithubFlowMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			gfd.mutation = mutation
			affected, err = gfd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(gfd.hooks) - 1; i >= 0; i-- {
			if gfd.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = gfd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, gfd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (gfd *GithubFlowDelete) ExecX(ctx context.Context) int {
	n, err := gfd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (gfd *GithubFlowDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: githubflow.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: githubflow.FieldID,
			},
		},
	}
	if ps := gfd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, gfd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	return affected, err
}

// GithubFlowDeleteOne is the builder for deleting a single GithubFlow entity.
type GithubFlowDeleteOne struct {
	gfd *GithubFlowDelete
}

// Exec executes the deletion query.
func (gfdo *GithubFlowDeleteOne) Exec(ctx context.Context) error {
	n, err := gfdo.gfd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{githubflow.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (gfdo *GithubFlowDeleteOne) ExecX(ctx context.Context) {
	gfdo.gfd.ExecX(ctx)
}
