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

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/internal/ent/magicflow"
	"github.com/loopholelabs/auth/internal/ent/predicate"
)

// MagicFlowDelete is the builder for deleting a MagicFlow entity.
type MagicFlowDelete struct {
	config
	hooks    []Hook
	mutation *MagicFlowMutation
}

// Where appends a list predicates to the MagicFlowDelete builder.
func (mfd *MagicFlowDelete) Where(ps ...predicate.MagicFlow) *MagicFlowDelete {
	mfd.mutation.Where(ps...)
	return mfd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (mfd *MagicFlowDelete) Exec(ctx context.Context) (int, error) {
	return withHooks[int, MagicFlowMutation](ctx, mfd.sqlExec, mfd.mutation, mfd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (mfd *MagicFlowDelete) ExecX(ctx context.Context) int {
	n, err := mfd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (mfd *MagicFlowDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: magicflow.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: magicflow.FieldID,
			},
		},
	}
	if ps := mfd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, mfd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	mfd.mutation.done = true
	return affected, err
}

// MagicFlowDeleteOne is the builder for deleting a single MagicFlow entity.
type MagicFlowDeleteOne struct {
	mfd *MagicFlowDelete
}

// Where appends a list predicates to the MagicFlowDelete builder.
func (mfdo *MagicFlowDeleteOne) Where(ps ...predicate.MagicFlow) *MagicFlowDeleteOne {
	mfdo.mfd.mutation.Where(ps...)
	return mfdo
}

// Exec executes the deletion query.
func (mfdo *MagicFlowDeleteOne) Exec(ctx context.Context) error {
	n, err := mfdo.mfd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{magicflow.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (mfdo *MagicFlowDeleteOne) ExecX(ctx context.Context) {
	if err := mfdo.Exec(ctx); err != nil {
		panic(err)
	}
}
