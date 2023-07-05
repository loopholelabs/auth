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
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/internal/ent/deviceflow"
	"github.com/loopholelabs/auth/internal/ent/predicate"
)

// DeviceFlowUpdate is the builder for updating DeviceFlow entities.
type DeviceFlowUpdate struct {
	config
	hooks    []Hook
	mutation *DeviceFlowMutation
}

// Where appends a list predicates to the DeviceFlowUpdate builder.
func (dfu *DeviceFlowUpdate) Where(ps ...predicate.DeviceFlow) *DeviceFlowUpdate {
	dfu.mutation.Where(ps...)
	return dfu
}

// SetLastPoll sets the "last_poll" field.
func (dfu *DeviceFlowUpdate) SetLastPoll(t time.Time) *DeviceFlowUpdate {
	dfu.mutation.SetLastPoll(t)
	return dfu
}

// SetNillableLastPoll sets the "last_poll" field if the given value is not nil.
func (dfu *DeviceFlowUpdate) SetNillableLastPoll(t *time.Time) *DeviceFlowUpdate {
	if t != nil {
		dfu.SetLastPoll(*t)
	}
	return dfu
}

// SetSession sets the "session" field.
func (dfu *DeviceFlowUpdate) SetSession(s string) *DeviceFlowUpdate {
	dfu.mutation.SetSession(s)
	return dfu
}

// SetNillableSession sets the "session" field if the given value is not nil.
func (dfu *DeviceFlowUpdate) SetNillableSession(s *string) *DeviceFlowUpdate {
	if s != nil {
		dfu.SetSession(*s)
	}
	return dfu
}

// ClearSession clears the value of the "session" field.
func (dfu *DeviceFlowUpdate) ClearSession() *DeviceFlowUpdate {
	dfu.mutation.ClearSession()
	return dfu
}

// SetExpiresAt sets the "expires_at" field.
func (dfu *DeviceFlowUpdate) SetExpiresAt(t time.Time) *DeviceFlowUpdate {
	dfu.mutation.SetExpiresAt(t)
	return dfu
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (dfu *DeviceFlowUpdate) SetNillableExpiresAt(t *time.Time) *DeviceFlowUpdate {
	if t != nil {
		dfu.SetExpiresAt(*t)
	}
	return dfu
}

// ClearExpiresAt clears the value of the "expires_at" field.
func (dfu *DeviceFlowUpdate) ClearExpiresAt() *DeviceFlowUpdate {
	dfu.mutation.ClearExpiresAt()
	return dfu
}

// Mutation returns the DeviceFlowMutation object of the builder.
func (dfu *DeviceFlowUpdate) Mutation() *DeviceFlowMutation {
	return dfu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (dfu *DeviceFlowUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, dfu.sqlSave, dfu.mutation, dfu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (dfu *DeviceFlowUpdate) SaveX(ctx context.Context) int {
	affected, err := dfu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (dfu *DeviceFlowUpdate) Exec(ctx context.Context) error {
	_, err := dfu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dfu *DeviceFlowUpdate) ExecX(ctx context.Context) {
	if err := dfu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (dfu *DeviceFlowUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(deviceflow.Table, deviceflow.Columns, sqlgraph.NewFieldSpec(deviceflow.FieldID, field.TypeInt))
	if ps := dfu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := dfu.mutation.LastPoll(); ok {
		_spec.SetField(deviceflow.FieldLastPoll, field.TypeTime, value)
	}
	if value, ok := dfu.mutation.Session(); ok {
		_spec.SetField(deviceflow.FieldSession, field.TypeString, value)
	}
	if dfu.mutation.SessionCleared() {
		_spec.ClearField(deviceflow.FieldSession, field.TypeString)
	}
	if value, ok := dfu.mutation.ExpiresAt(); ok {
		_spec.SetField(deviceflow.FieldExpiresAt, field.TypeTime, value)
	}
	if dfu.mutation.ExpiresAtCleared() {
		_spec.ClearField(deviceflow.FieldExpiresAt, field.TypeTime)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, dfu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{deviceflow.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	dfu.mutation.done = true
	return n, nil
}

// DeviceFlowUpdateOne is the builder for updating a single DeviceFlow entity.
type DeviceFlowUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *DeviceFlowMutation
}

// SetLastPoll sets the "last_poll" field.
func (dfuo *DeviceFlowUpdateOne) SetLastPoll(t time.Time) *DeviceFlowUpdateOne {
	dfuo.mutation.SetLastPoll(t)
	return dfuo
}

// SetNillableLastPoll sets the "last_poll" field if the given value is not nil.
func (dfuo *DeviceFlowUpdateOne) SetNillableLastPoll(t *time.Time) *DeviceFlowUpdateOne {
	if t != nil {
		dfuo.SetLastPoll(*t)
	}
	return dfuo
}

// SetSession sets the "session" field.
func (dfuo *DeviceFlowUpdateOne) SetSession(s string) *DeviceFlowUpdateOne {
	dfuo.mutation.SetSession(s)
	return dfuo
}

// SetNillableSession sets the "session" field if the given value is not nil.
func (dfuo *DeviceFlowUpdateOne) SetNillableSession(s *string) *DeviceFlowUpdateOne {
	if s != nil {
		dfuo.SetSession(*s)
	}
	return dfuo
}

// ClearSession clears the value of the "session" field.
func (dfuo *DeviceFlowUpdateOne) ClearSession() *DeviceFlowUpdateOne {
	dfuo.mutation.ClearSession()
	return dfuo
}

// SetExpiresAt sets the "expires_at" field.
func (dfuo *DeviceFlowUpdateOne) SetExpiresAt(t time.Time) *DeviceFlowUpdateOne {
	dfuo.mutation.SetExpiresAt(t)
	return dfuo
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (dfuo *DeviceFlowUpdateOne) SetNillableExpiresAt(t *time.Time) *DeviceFlowUpdateOne {
	if t != nil {
		dfuo.SetExpiresAt(*t)
	}
	return dfuo
}

// ClearExpiresAt clears the value of the "expires_at" field.
func (dfuo *DeviceFlowUpdateOne) ClearExpiresAt() *DeviceFlowUpdateOne {
	dfuo.mutation.ClearExpiresAt()
	return dfuo
}

// Mutation returns the DeviceFlowMutation object of the builder.
func (dfuo *DeviceFlowUpdateOne) Mutation() *DeviceFlowMutation {
	return dfuo.mutation
}

// Where appends a list predicates to the DeviceFlowUpdate builder.
func (dfuo *DeviceFlowUpdateOne) Where(ps ...predicate.DeviceFlow) *DeviceFlowUpdateOne {
	dfuo.mutation.Where(ps...)
	return dfuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (dfuo *DeviceFlowUpdateOne) Select(field string, fields ...string) *DeviceFlowUpdateOne {
	dfuo.fields = append([]string{field}, fields...)
	return dfuo
}

// Save executes the query and returns the updated DeviceFlow entity.
func (dfuo *DeviceFlowUpdateOne) Save(ctx context.Context) (*DeviceFlow, error) {
	return withHooks(ctx, dfuo.sqlSave, dfuo.mutation, dfuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (dfuo *DeviceFlowUpdateOne) SaveX(ctx context.Context) *DeviceFlow {
	node, err := dfuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (dfuo *DeviceFlowUpdateOne) Exec(ctx context.Context) error {
	_, err := dfuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dfuo *DeviceFlowUpdateOne) ExecX(ctx context.Context) {
	if err := dfuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (dfuo *DeviceFlowUpdateOne) sqlSave(ctx context.Context) (_node *DeviceFlow, err error) {
	_spec := sqlgraph.NewUpdateSpec(deviceflow.Table, deviceflow.Columns, sqlgraph.NewFieldSpec(deviceflow.FieldID, field.TypeInt))
	id, ok := dfuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "DeviceFlow.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := dfuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, deviceflow.FieldID)
		for _, f := range fields {
			if !deviceflow.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != deviceflow.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := dfuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := dfuo.mutation.LastPoll(); ok {
		_spec.SetField(deviceflow.FieldLastPoll, field.TypeTime, value)
	}
	if value, ok := dfuo.mutation.Session(); ok {
		_spec.SetField(deviceflow.FieldSession, field.TypeString, value)
	}
	if dfuo.mutation.SessionCleared() {
		_spec.ClearField(deviceflow.FieldSession, field.TypeString)
	}
	if value, ok := dfuo.mutation.ExpiresAt(); ok {
		_spec.SetField(deviceflow.FieldExpiresAt, field.TypeTime, value)
	}
	if dfuo.mutation.ExpiresAtCleared() {
		_spec.ClearField(deviceflow.FieldExpiresAt, field.TypeTime)
	}
	_node = &DeviceFlow{config: dfuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, dfuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{deviceflow.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	dfuo.mutation.done = true
	return _node, nil
}
