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
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/internal/ent/magicflow"
	"github.com/loopholelabs/auth/internal/ent/predicate"
)

// MagicFlowUpdate is the builder for updating MagicFlow entities.
type MagicFlowUpdate struct {
	config
	hooks    []Hook
	mutation *MagicFlowMutation
}

// Where appends a list predicates to the MagicFlowUpdate builder.
func (mfu *MagicFlowUpdate) Where(ps ...predicate.MagicFlow) *MagicFlowUpdate {
	mfu.mutation.Where(ps...)
	return mfu
}

// Mutation returns the MagicFlowMutation object of the builder.
func (mfu *MagicFlowUpdate) Mutation() *MagicFlowMutation {
	return mfu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (mfu *MagicFlowUpdate) Save(ctx context.Context) (int, error) {
	return withHooks[int, MagicFlowMutation](ctx, mfu.sqlSave, mfu.mutation, mfu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (mfu *MagicFlowUpdate) SaveX(ctx context.Context) int {
	affected, err := mfu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (mfu *MagicFlowUpdate) Exec(ctx context.Context) error {
	_, err := mfu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mfu *MagicFlowUpdate) ExecX(ctx context.Context) {
	if err := mfu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (mfu *MagicFlowUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   magicflow.Table,
			Columns: magicflow.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: magicflow.FieldID,
			},
		},
	}
	if ps := mfu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if mfu.mutation.OrganizationCleared() {
		_spec.ClearField(magicflow.FieldOrganization, field.TypeString)
	}
	if mfu.mutation.DeviceIdentifierCleared() {
		_spec.ClearField(magicflow.FieldDeviceIdentifier, field.TypeString)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, mfu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{magicflow.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	mfu.mutation.done = true
	return n, nil
}

// MagicFlowUpdateOne is the builder for updating a single MagicFlow entity.
type MagicFlowUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *MagicFlowMutation
}

// Mutation returns the MagicFlowMutation object of the builder.
func (mfuo *MagicFlowUpdateOne) Mutation() *MagicFlowMutation {
	return mfuo.mutation
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (mfuo *MagicFlowUpdateOne) Select(field string, fields ...string) *MagicFlowUpdateOne {
	mfuo.fields = append([]string{field}, fields...)
	return mfuo
}

// Save executes the query and returns the updated MagicFlow entity.
func (mfuo *MagicFlowUpdateOne) Save(ctx context.Context) (*MagicFlow, error) {
	return withHooks[*MagicFlow, MagicFlowMutation](ctx, mfuo.sqlSave, mfuo.mutation, mfuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (mfuo *MagicFlowUpdateOne) SaveX(ctx context.Context) *MagicFlow {
	node, err := mfuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (mfuo *MagicFlowUpdateOne) Exec(ctx context.Context) error {
	_, err := mfuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mfuo *MagicFlowUpdateOne) ExecX(ctx context.Context) {
	if err := mfuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (mfuo *MagicFlowUpdateOne) sqlSave(ctx context.Context) (_node *MagicFlow, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   magicflow.Table,
			Columns: magicflow.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: magicflow.FieldID,
			},
		},
	}
	id, ok := mfuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "MagicFlow.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := mfuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, magicflow.FieldID)
		for _, f := range fields {
			if !magicflow.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != magicflow.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := mfuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if mfuo.mutation.OrganizationCleared() {
		_spec.ClearField(magicflow.FieldOrganization, field.TypeString)
	}
	if mfuo.mutation.DeviceIdentifierCleared() {
		_spec.ClearField(magicflow.FieldDeviceIdentifier, field.TypeString)
	}
	_node = &MagicFlow{config: mfuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, mfuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{magicflow.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	mfuo.mutation.done = true
	return _node, nil
}
