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
	"github.com/loopholelabs/auth/internal/ent/magicflow"
)

// MagicFlowCreate is the builder for creating a MagicFlow entity.
type MagicFlowCreate struct {
	config
	mutation *MagicFlowMutation
	hooks    []Hook
}

// SetCreatedAt sets the "created_at" field.
func (mfc *MagicFlowCreate) SetCreatedAt(t time.Time) *MagicFlowCreate {
	mfc.mutation.SetCreatedAt(t)
	return mfc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (mfc *MagicFlowCreate) SetNillableCreatedAt(t *time.Time) *MagicFlowCreate {
	if t != nil {
		mfc.SetCreatedAt(*t)
	}
	return mfc
}

// SetEmail sets the "email" field.
func (mfc *MagicFlowCreate) SetEmail(s string) *MagicFlowCreate {
	mfc.mutation.SetEmail(s)
	return mfc
}

// SetIPAddress sets the "ip_address" field.
func (mfc *MagicFlowCreate) SetIPAddress(s string) *MagicFlowCreate {
	mfc.mutation.SetIPAddress(s)
	return mfc
}

// SetSecret sets the "secret" field.
func (mfc *MagicFlowCreate) SetSecret(s string) *MagicFlowCreate {
	mfc.mutation.SetSecret(s)
	return mfc
}

// SetNextURL sets the "next_url" field.
func (mfc *MagicFlowCreate) SetNextURL(s string) *MagicFlowCreate {
	mfc.mutation.SetNextURL(s)
	return mfc
}

// SetOrganization sets the "organization" field.
func (mfc *MagicFlowCreate) SetOrganization(s string) *MagicFlowCreate {
	mfc.mutation.SetOrganization(s)
	return mfc
}

// SetNillableOrganization sets the "organization" field if the given value is not nil.
func (mfc *MagicFlowCreate) SetNillableOrganization(s *string) *MagicFlowCreate {
	if s != nil {
		mfc.SetOrganization(*s)
	}
	return mfc
}

// SetDeviceIdentifier sets the "device_identifier" field.
func (mfc *MagicFlowCreate) SetDeviceIdentifier(s string) *MagicFlowCreate {
	mfc.mutation.SetDeviceIdentifier(s)
	return mfc
}

// SetNillableDeviceIdentifier sets the "device_identifier" field if the given value is not nil.
func (mfc *MagicFlowCreate) SetNillableDeviceIdentifier(s *string) *MagicFlowCreate {
	if s != nil {
		mfc.SetDeviceIdentifier(*s)
	}
	return mfc
}

// Mutation returns the MagicFlowMutation object of the builder.
func (mfc *MagicFlowCreate) Mutation() *MagicFlowMutation {
	return mfc.mutation
}

// Save creates the MagicFlow in the database.
func (mfc *MagicFlowCreate) Save(ctx context.Context) (*MagicFlow, error) {
	var (
		err  error
		node *MagicFlow
	)
	mfc.defaults()
	if len(mfc.hooks) == 0 {
		if err = mfc.check(); err != nil {
			return nil, err
		}
		node, err = mfc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*MagicFlowMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = mfc.check(); err != nil {
				return nil, err
			}
			mfc.mutation = mutation
			if node, err = mfc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(mfc.hooks) - 1; i >= 0; i-- {
			if mfc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = mfc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, mfc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*MagicFlow)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from MagicFlowMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (mfc *MagicFlowCreate) SaveX(ctx context.Context) *MagicFlow {
	v, err := mfc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (mfc *MagicFlowCreate) Exec(ctx context.Context) error {
	_, err := mfc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mfc *MagicFlowCreate) ExecX(ctx context.Context) {
	if err := mfc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (mfc *MagicFlowCreate) defaults() {
	if _, ok := mfc.mutation.CreatedAt(); !ok {
		v := magicflow.DefaultCreatedAt()
		mfc.mutation.SetCreatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (mfc *MagicFlowCreate) check() error {
	if _, ok := mfc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "MagicFlow.created_at"`)}
	}
	if _, ok := mfc.mutation.Email(); !ok {
		return &ValidationError{Name: "email", err: errors.New(`ent: missing required field "MagicFlow.email"`)}
	}
	if v, ok := mfc.mutation.Email(); ok {
		if err := magicflow.EmailValidator(v); err != nil {
			return &ValidationError{Name: "email", err: fmt.Errorf(`ent: validator failed for field "MagicFlow.email": %w`, err)}
		}
	}
	if _, ok := mfc.mutation.IPAddress(); !ok {
		return &ValidationError{Name: "ip_address", err: errors.New(`ent: missing required field "MagicFlow.ip_address"`)}
	}
	if v, ok := mfc.mutation.IPAddress(); ok {
		if err := magicflow.IPAddressValidator(v); err != nil {
			return &ValidationError{Name: "ip_address", err: fmt.Errorf(`ent: validator failed for field "MagicFlow.ip_address": %w`, err)}
		}
	}
	if _, ok := mfc.mutation.Secret(); !ok {
		return &ValidationError{Name: "secret", err: errors.New(`ent: missing required field "MagicFlow.secret"`)}
	}
	if v, ok := mfc.mutation.Secret(); ok {
		if err := magicflow.SecretValidator(v); err != nil {
			return &ValidationError{Name: "secret", err: fmt.Errorf(`ent: validator failed for field "MagicFlow.secret": %w`, err)}
		}
	}
	if _, ok := mfc.mutation.NextURL(); !ok {
		return &ValidationError{Name: "next_url", err: errors.New(`ent: missing required field "MagicFlow.next_url"`)}
	}
	if v, ok := mfc.mutation.NextURL(); ok {
		if err := magicflow.NextURLValidator(v); err != nil {
			return &ValidationError{Name: "next_url", err: fmt.Errorf(`ent: validator failed for field "MagicFlow.next_url": %w`, err)}
		}
	}
	return nil
}

func (mfc *MagicFlowCreate) sqlSave(ctx context.Context) (*MagicFlow, error) {
	_node, _spec := mfc.createSpec()
	if err := sqlgraph.CreateNode(ctx, mfc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (mfc *MagicFlowCreate) createSpec() (*MagicFlow, *sqlgraph.CreateSpec) {
	var (
		_node = &MagicFlow{config: mfc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: magicflow.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: magicflow.FieldID,
			},
		}
	)
	if value, ok := mfc.mutation.CreatedAt(); ok {
		_spec.SetField(magicflow.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := mfc.mutation.Email(); ok {
		_spec.SetField(magicflow.FieldEmail, field.TypeString, value)
		_node.Email = value
	}
	if value, ok := mfc.mutation.IPAddress(); ok {
		_spec.SetField(magicflow.FieldIPAddress, field.TypeString, value)
		_node.IPAddress = value
	}
	if value, ok := mfc.mutation.Secret(); ok {
		_spec.SetField(magicflow.FieldSecret, field.TypeString, value)
		_node.Secret = value
	}
	if value, ok := mfc.mutation.NextURL(); ok {
		_spec.SetField(magicflow.FieldNextURL, field.TypeString, value)
		_node.NextURL = value
	}
	if value, ok := mfc.mutation.Organization(); ok {
		_spec.SetField(magicflow.FieldOrganization, field.TypeString, value)
		_node.Organization = value
	}
	if value, ok := mfc.mutation.DeviceIdentifier(); ok {
		_spec.SetField(magicflow.FieldDeviceIdentifier, field.TypeString, value)
		_node.DeviceIdentifier = value
	}
	return _node, _spec
}

// MagicFlowCreateBulk is the builder for creating many MagicFlow entities in bulk.
type MagicFlowCreateBulk struct {
	config
	builders []*MagicFlowCreate
}

// Save creates the MagicFlow entities in the database.
func (mfcb *MagicFlowCreateBulk) Save(ctx context.Context) ([]*MagicFlow, error) {
	specs := make([]*sqlgraph.CreateSpec, len(mfcb.builders))
	nodes := make([]*MagicFlow, len(mfcb.builders))
	mutators := make([]Mutator, len(mfcb.builders))
	for i := range mfcb.builders {
		func(i int, root context.Context) {
			builder := mfcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*MagicFlowMutation)
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
					_, err = mutators[i+1].Mutate(root, mfcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, mfcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, mfcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (mfcb *MagicFlowCreateBulk) SaveX(ctx context.Context) []*MagicFlow {
	v, err := mfcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (mfcb *MagicFlowCreateBulk) Exec(ctx context.Context) error {
	_, err := mfcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mfcb *MagicFlowCreateBulk) ExecX(ctx context.Context) {
	if err := mfcb.Exec(ctx); err != nil {
		panic(err)
	}
}
