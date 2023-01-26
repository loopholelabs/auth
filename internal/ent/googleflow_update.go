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
	"github.com/loopholelabs/auth/internal/ent/googleflow"
	"github.com/loopholelabs/auth/internal/ent/predicate"
)

// GoogleFlowUpdate is the builder for updating GoogleFlow entities.
type GoogleFlowUpdate struct {
	config
	hooks    []Hook
	mutation *GoogleFlowMutation
}

// Where appends a list predicates to the GoogleFlowUpdate builder.
func (gfu *GoogleFlowUpdate) Where(ps ...predicate.GoogleFlow) *GoogleFlowUpdate {
	gfu.mutation.Where(ps...)
	return gfu
}

// Mutation returns the GoogleFlowMutation object of the builder.
func (gfu *GoogleFlowUpdate) Mutation() *GoogleFlowMutation {
	return gfu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (gfu *GoogleFlowUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(gfu.hooks) == 0 {
		affected, err = gfu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*GoogleFlowMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			gfu.mutation = mutation
			affected, err = gfu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(gfu.hooks) - 1; i >= 0; i-- {
			if gfu.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = gfu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, gfu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (gfu *GoogleFlowUpdate) SaveX(ctx context.Context) int {
	affected, err := gfu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (gfu *GoogleFlowUpdate) Exec(ctx context.Context) error {
	_, err := gfu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (gfu *GoogleFlowUpdate) ExecX(ctx context.Context) {
	if err := gfu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (gfu *GoogleFlowUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   googleflow.Table,
			Columns: googleflow.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: googleflow.FieldID,
			},
		},
	}
	if ps := gfu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if gfu.mutation.OrganizationCleared() {
		_spec.ClearField(googleflow.FieldOrganization, field.TypeString)
	}
	if gfu.mutation.DeviceIdentifierCleared() {
		_spec.ClearField(googleflow.FieldDeviceIdentifier, field.TypeString)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, gfu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{googleflow.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// GoogleFlowUpdateOne is the builder for updating a single GoogleFlow entity.
type GoogleFlowUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *GoogleFlowMutation
}

// Mutation returns the GoogleFlowMutation object of the builder.
func (gfuo *GoogleFlowUpdateOne) Mutation() *GoogleFlowMutation {
	return gfuo.mutation
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (gfuo *GoogleFlowUpdateOne) Select(field string, fields ...string) *GoogleFlowUpdateOne {
	gfuo.fields = append([]string{field}, fields...)
	return gfuo
}

// Save executes the query and returns the updated GoogleFlow entity.
func (gfuo *GoogleFlowUpdateOne) Save(ctx context.Context) (*GoogleFlow, error) {
	var (
		err  error
		node *GoogleFlow
	)
	if len(gfuo.hooks) == 0 {
		node, err = gfuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*GoogleFlowMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			gfuo.mutation = mutation
			node, err = gfuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(gfuo.hooks) - 1; i >= 0; i-- {
			if gfuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = gfuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, gfuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*GoogleFlow)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from GoogleFlowMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (gfuo *GoogleFlowUpdateOne) SaveX(ctx context.Context) *GoogleFlow {
	node, err := gfuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (gfuo *GoogleFlowUpdateOne) Exec(ctx context.Context) error {
	_, err := gfuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (gfuo *GoogleFlowUpdateOne) ExecX(ctx context.Context) {
	if err := gfuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (gfuo *GoogleFlowUpdateOne) sqlSave(ctx context.Context) (_node *GoogleFlow, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   googleflow.Table,
			Columns: googleflow.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: googleflow.FieldID,
			},
		},
	}
	id, ok := gfuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "GoogleFlow.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := gfuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, googleflow.FieldID)
		for _, f := range fields {
			if !googleflow.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != googleflow.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := gfuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if gfuo.mutation.OrganizationCleared() {
		_spec.ClearField(googleflow.FieldOrganization, field.TypeString)
	}
	if gfuo.mutation.DeviceIdentifierCleared() {
		_spec.ClearField(googleflow.FieldDeviceIdentifier, field.TypeString)
	}
	_node = &GoogleFlow{config: gfuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, gfuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{googleflow.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}