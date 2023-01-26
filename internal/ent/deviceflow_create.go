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

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/internal/ent/deviceflow"
)

// DeviceFlowCreate is the builder for creating a DeviceFlow entity.
type DeviceFlowCreate struct {
	config
	mutation *DeviceFlowMutation
	hooks    []Hook
}

// SetCreatedAt sets the "created_at" field.
func (dfc *DeviceFlowCreate) SetCreatedAt(t time.Time) *DeviceFlowCreate {
	dfc.mutation.SetCreatedAt(t)
	return dfc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (dfc *DeviceFlowCreate) SetNillableCreatedAt(t *time.Time) *DeviceFlowCreate {
	if t != nil {
		dfc.SetCreatedAt(*t)
	}
	return dfc
}

// SetLastPoll sets the "last_poll" field.
func (dfc *DeviceFlowCreate) SetLastPoll(t time.Time) *DeviceFlowCreate {
	dfc.mutation.SetLastPoll(t)
	return dfc
}

// SetNillableLastPoll sets the "last_poll" field if the given value is not nil.
func (dfc *DeviceFlowCreate) SetNillableLastPoll(t *time.Time) *DeviceFlowCreate {
	if t != nil {
		dfc.SetLastPoll(*t)
	}
	return dfc
}

// SetIdentifier sets the "identifier" field.
func (dfc *DeviceFlowCreate) SetIdentifier(s string) *DeviceFlowCreate {
	dfc.mutation.SetIdentifier(s)
	return dfc
}

// SetDeviceCode sets the "device_code" field.
func (dfc *DeviceFlowCreate) SetDeviceCode(s string) *DeviceFlowCreate {
	dfc.mutation.SetDeviceCode(s)
	return dfc
}

// SetUserCode sets the "user_code" field.
func (dfc *DeviceFlowCreate) SetUserCode(s string) *DeviceFlowCreate {
	dfc.mutation.SetUserCode(s)
	return dfc
}

// SetSession sets the "session" field.
func (dfc *DeviceFlowCreate) SetSession(s string) *DeviceFlowCreate {
	dfc.mutation.SetSession(s)
	return dfc
}

// SetNillableSession sets the "session" field if the given value is not nil.
func (dfc *DeviceFlowCreate) SetNillableSession(s *string) *DeviceFlowCreate {
	if s != nil {
		dfc.SetSession(*s)
	}
	return dfc
}

// SetExpiresAt sets the "expires_at" field.
func (dfc *DeviceFlowCreate) SetExpiresAt(t time.Time) *DeviceFlowCreate {
	dfc.mutation.SetExpiresAt(t)
	return dfc
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (dfc *DeviceFlowCreate) SetNillableExpiresAt(t *time.Time) *DeviceFlowCreate {
	if t != nil {
		dfc.SetExpiresAt(*t)
	}
	return dfc
}

// Mutation returns the DeviceFlowMutation object of the builder.
func (dfc *DeviceFlowCreate) Mutation() *DeviceFlowMutation {
	return dfc.mutation
}

// Save creates the DeviceFlow in the database.
func (dfc *DeviceFlowCreate) Save(ctx context.Context) (*DeviceFlow, error) {
	var (
		err  error
		node *DeviceFlow
	)
	dfc.defaults()
	if len(dfc.hooks) == 0 {
		if err = dfc.check(); err != nil {
			return nil, err
		}
		node, err = dfc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DeviceFlowMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = dfc.check(); err != nil {
				return nil, err
			}
			dfc.mutation = mutation
			if node, err = dfc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(dfc.hooks) - 1; i >= 0; i-- {
			if dfc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = dfc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, dfc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*DeviceFlow)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from DeviceFlowMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (dfc *DeviceFlowCreate) SaveX(ctx context.Context) *DeviceFlow {
	v, err := dfc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dfc *DeviceFlowCreate) Exec(ctx context.Context) error {
	_, err := dfc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dfc *DeviceFlowCreate) ExecX(ctx context.Context) {
	if err := dfc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (dfc *DeviceFlowCreate) defaults() {
	if _, ok := dfc.mutation.CreatedAt(); !ok {
		v := deviceflow.DefaultCreatedAt()
		dfc.mutation.SetCreatedAt(v)
	}
	if _, ok := dfc.mutation.LastPoll(); !ok {
		v := deviceflow.DefaultLastPoll()
		dfc.mutation.SetLastPoll(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (dfc *DeviceFlowCreate) check() error {
	if _, ok := dfc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "DeviceFlow.created_at"`)}
	}
	if _, ok := dfc.mutation.LastPoll(); !ok {
		return &ValidationError{Name: "last_poll", err: errors.New(`ent: missing required field "DeviceFlow.last_poll"`)}
	}
	if _, ok := dfc.mutation.Identifier(); !ok {
		return &ValidationError{Name: "identifier", err: errors.New(`ent: missing required field "DeviceFlow.identifier"`)}
	}
	if v, ok := dfc.mutation.Identifier(); ok {
		if err := deviceflow.IdentifierValidator(v); err != nil {
			return &ValidationError{Name: "identifier", err: fmt.Errorf(`ent: validator failed for field "DeviceFlow.identifier": %w`, err)}
		}
	}
	if _, ok := dfc.mutation.DeviceCode(); !ok {
		return &ValidationError{Name: "device_code", err: errors.New(`ent: missing required field "DeviceFlow.device_code"`)}
	}
	if v, ok := dfc.mutation.DeviceCode(); ok {
		if err := deviceflow.DeviceCodeValidator(v); err != nil {
			return &ValidationError{Name: "device_code", err: fmt.Errorf(`ent: validator failed for field "DeviceFlow.device_code": %w`, err)}
		}
	}
	if _, ok := dfc.mutation.UserCode(); !ok {
		return &ValidationError{Name: "user_code", err: errors.New(`ent: missing required field "DeviceFlow.user_code"`)}
	}
	if v, ok := dfc.mutation.UserCode(); ok {
		if err := deviceflow.UserCodeValidator(v); err != nil {
			return &ValidationError{Name: "user_code", err: fmt.Errorf(`ent: validator failed for field "DeviceFlow.user_code": %w`, err)}
		}
	}
	return nil
}

func (dfc *DeviceFlowCreate) sqlSave(ctx context.Context) (*DeviceFlow, error) {
	_node, _spec := dfc.createSpec()
	if err := sqlgraph.CreateNode(ctx, dfc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (dfc *DeviceFlowCreate) createSpec() (*DeviceFlow, *sqlgraph.CreateSpec) {
	var (
		_node = &DeviceFlow{config: dfc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: deviceflow.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: deviceflow.FieldID,
			},
		}
	)
	if value, ok := dfc.mutation.CreatedAt(); ok {
		_spec.SetField(deviceflow.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := dfc.mutation.LastPoll(); ok {
		_spec.SetField(deviceflow.FieldLastPoll, field.TypeTime, value)
		_node.LastPoll = value
	}
	if value, ok := dfc.mutation.Identifier(); ok {
		_spec.SetField(deviceflow.FieldIdentifier, field.TypeString, value)
		_node.Identifier = value
	}
	if value, ok := dfc.mutation.DeviceCode(); ok {
		_spec.SetField(deviceflow.FieldDeviceCode, field.TypeString, value)
		_node.DeviceCode = value
	}
	if value, ok := dfc.mutation.UserCode(); ok {
		_spec.SetField(deviceflow.FieldUserCode, field.TypeString, value)
		_node.UserCode = value
	}
	if value, ok := dfc.mutation.Session(); ok {
		_spec.SetField(deviceflow.FieldSession, field.TypeString, value)
		_node.Session = value
	}
	if value, ok := dfc.mutation.ExpiresAt(); ok {
		_spec.SetField(deviceflow.FieldExpiresAt, field.TypeTime, value)
		_node.ExpiresAt = value
	}
	return _node, _spec
}

// DeviceFlowCreateBulk is the builder for creating many DeviceFlow entities in bulk.
type DeviceFlowCreateBulk struct {
	config
	builders []*DeviceFlowCreate
}

// Save creates the DeviceFlow entities in the database.
func (dfcb *DeviceFlowCreateBulk) Save(ctx context.Context) ([]*DeviceFlow, error) {
	specs := make([]*sqlgraph.CreateSpec, len(dfcb.builders))
	nodes := make([]*DeviceFlow, len(dfcb.builders))
	mutators := make([]Mutator, len(dfcb.builders))
	for i := range dfcb.builders {
		func(i int, root context.Context) {
			builder := dfcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DeviceFlowMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, dfcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, dfcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, dfcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (dfcb *DeviceFlowCreateBulk) SaveX(ctx context.Context) []*DeviceFlow {
	v, err := dfcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dfcb *DeviceFlowCreateBulk) Exec(ctx context.Context) error {
	_, err := dfcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dfcb *DeviceFlowCreateBulk) ExecX(ctx context.Context) {
	if err := dfcb.Exec(ctx); err != nil {
		panic(err)
	}
}
