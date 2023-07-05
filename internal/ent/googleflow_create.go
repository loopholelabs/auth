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
	"github.com/loopholelabs/auth/internal/ent/googleflow"
)

// GoogleFlowCreate is the builder for creating a GoogleFlow entity.
type GoogleFlowCreate struct {
	config
	mutation *GoogleFlowMutation
	hooks    []Hook
}

// SetCreatedAt sets the "created_at" field.
func (gfc *GoogleFlowCreate) SetCreatedAt(t time.Time) *GoogleFlowCreate {
	gfc.mutation.SetCreatedAt(t)
	return gfc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (gfc *GoogleFlowCreate) SetNillableCreatedAt(t *time.Time) *GoogleFlowCreate {
	if t != nil {
		gfc.SetCreatedAt(*t)
	}
	return gfc
}

// SetState sets the "state" field.
func (gfc *GoogleFlowCreate) SetState(s string) *GoogleFlowCreate {
	gfc.mutation.SetState(s)
	return gfc
}

// SetVerifier sets the "verifier" field.
func (gfc *GoogleFlowCreate) SetVerifier(s string) *GoogleFlowCreate {
	gfc.mutation.SetVerifier(s)
	return gfc
}

// SetChallenge sets the "challenge" field.
func (gfc *GoogleFlowCreate) SetChallenge(s string) *GoogleFlowCreate {
	gfc.mutation.SetChallenge(s)
	return gfc
}

// SetNextURL sets the "next_url" field.
func (gfc *GoogleFlowCreate) SetNextURL(s string) *GoogleFlowCreate {
	gfc.mutation.SetNextURL(s)
	return gfc
}

// SetOrganization sets the "organization" field.
func (gfc *GoogleFlowCreate) SetOrganization(s string) *GoogleFlowCreate {
	gfc.mutation.SetOrganization(s)
	return gfc
}

// SetNillableOrganization sets the "organization" field if the given value is not nil.
func (gfc *GoogleFlowCreate) SetNillableOrganization(s *string) *GoogleFlowCreate {
	if s != nil {
		gfc.SetOrganization(*s)
	}
	return gfc
}

// SetDeviceIdentifier sets the "device_identifier" field.
func (gfc *GoogleFlowCreate) SetDeviceIdentifier(s string) *GoogleFlowCreate {
	gfc.mutation.SetDeviceIdentifier(s)
	return gfc
}

// SetNillableDeviceIdentifier sets the "device_identifier" field if the given value is not nil.
func (gfc *GoogleFlowCreate) SetNillableDeviceIdentifier(s *string) *GoogleFlowCreate {
	if s != nil {
		gfc.SetDeviceIdentifier(*s)
	}
	return gfc
}

// Mutation returns the GoogleFlowMutation object of the builder.
func (gfc *GoogleFlowCreate) Mutation() *GoogleFlowMutation {
	return gfc.mutation
}

// Save creates the GoogleFlow in the database.
func (gfc *GoogleFlowCreate) Save(ctx context.Context) (*GoogleFlow, error) {
	gfc.defaults()
	return withHooks(ctx, gfc.sqlSave, gfc.mutation, gfc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (gfc *GoogleFlowCreate) SaveX(ctx context.Context) *GoogleFlow {
	v, err := gfc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (gfc *GoogleFlowCreate) Exec(ctx context.Context) error {
	_, err := gfc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (gfc *GoogleFlowCreate) ExecX(ctx context.Context) {
	if err := gfc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (gfc *GoogleFlowCreate) defaults() {
	if _, ok := gfc.mutation.CreatedAt(); !ok {
		v := googleflow.DefaultCreatedAt()
		gfc.mutation.SetCreatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (gfc *GoogleFlowCreate) check() error {
	if _, ok := gfc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "GoogleFlow.created_at"`)}
	}
	if _, ok := gfc.mutation.State(); !ok {
		return &ValidationError{Name: "state", err: errors.New(`ent: missing required field "GoogleFlow.state"`)}
	}
	if v, ok := gfc.mutation.State(); ok {
		if err := googleflow.StateValidator(v); err != nil {
			return &ValidationError{Name: "state", err: fmt.Errorf(`ent: validator failed for field "GoogleFlow.state": %w`, err)}
		}
	}
	if _, ok := gfc.mutation.Verifier(); !ok {
		return &ValidationError{Name: "verifier", err: errors.New(`ent: missing required field "GoogleFlow.verifier"`)}
	}
	if v, ok := gfc.mutation.Verifier(); ok {
		if err := googleflow.VerifierValidator(v); err != nil {
			return &ValidationError{Name: "verifier", err: fmt.Errorf(`ent: validator failed for field "GoogleFlow.verifier": %w`, err)}
		}
	}
	if _, ok := gfc.mutation.Challenge(); !ok {
		return &ValidationError{Name: "challenge", err: errors.New(`ent: missing required field "GoogleFlow.challenge"`)}
	}
	if v, ok := gfc.mutation.Challenge(); ok {
		if err := googleflow.ChallengeValidator(v); err != nil {
			return &ValidationError{Name: "challenge", err: fmt.Errorf(`ent: validator failed for field "GoogleFlow.challenge": %w`, err)}
		}
	}
	if _, ok := gfc.mutation.NextURL(); !ok {
		return &ValidationError{Name: "next_url", err: errors.New(`ent: missing required field "GoogleFlow.next_url"`)}
	}
	if v, ok := gfc.mutation.NextURL(); ok {
		if err := googleflow.NextURLValidator(v); err != nil {
			return &ValidationError{Name: "next_url", err: fmt.Errorf(`ent: validator failed for field "GoogleFlow.next_url": %w`, err)}
		}
	}
	return nil
}

func (gfc *GoogleFlowCreate) sqlSave(ctx context.Context) (*GoogleFlow, error) {
	if err := gfc.check(); err != nil {
		return nil, err
	}
	_node, _spec := gfc.createSpec()
	if err := sqlgraph.CreateNode(ctx, gfc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	gfc.mutation.id = &_node.ID
	gfc.mutation.done = true
	return _node, nil
}

func (gfc *GoogleFlowCreate) createSpec() (*GoogleFlow, *sqlgraph.CreateSpec) {
	var (
		_node = &GoogleFlow{config: gfc.config}
		_spec = sqlgraph.NewCreateSpec(googleflow.Table, sqlgraph.NewFieldSpec(googleflow.FieldID, field.TypeInt))
	)
	if value, ok := gfc.mutation.CreatedAt(); ok {
		_spec.SetField(googleflow.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := gfc.mutation.State(); ok {
		_spec.SetField(googleflow.FieldState, field.TypeString, value)
		_node.State = value
	}
	if value, ok := gfc.mutation.Verifier(); ok {
		_spec.SetField(googleflow.FieldVerifier, field.TypeString, value)
		_node.Verifier = value
	}
	if value, ok := gfc.mutation.Challenge(); ok {
		_spec.SetField(googleflow.FieldChallenge, field.TypeString, value)
		_node.Challenge = value
	}
	if value, ok := gfc.mutation.NextURL(); ok {
		_spec.SetField(googleflow.FieldNextURL, field.TypeString, value)
		_node.NextURL = value
	}
	if value, ok := gfc.mutation.Organization(); ok {
		_spec.SetField(googleflow.FieldOrganization, field.TypeString, value)
		_node.Organization = value
	}
	if value, ok := gfc.mutation.DeviceIdentifier(); ok {
		_spec.SetField(googleflow.FieldDeviceIdentifier, field.TypeString, value)
		_node.DeviceIdentifier = value
	}
	return _node, _spec
}

// GoogleFlowCreateBulk is the builder for creating many GoogleFlow entities in bulk.
type GoogleFlowCreateBulk struct {
	config
	builders []*GoogleFlowCreate
}

// Save creates the GoogleFlow entities in the database.
func (gfcb *GoogleFlowCreateBulk) Save(ctx context.Context) ([]*GoogleFlow, error) {
	specs := make([]*sqlgraph.CreateSpec, len(gfcb.builders))
	nodes := make([]*GoogleFlow, len(gfcb.builders))
	mutators := make([]Mutator, len(gfcb.builders))
	for i := range gfcb.builders {
		func(i int, root context.Context) {
			builder := gfcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*GoogleFlowMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, gfcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, gfcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, gfcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (gfcb *GoogleFlowCreateBulk) SaveX(ctx context.Context) []*GoogleFlow {
	v, err := gfcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (gfcb *GoogleFlowCreateBulk) Exec(ctx context.Context) error {
	_, err := gfcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (gfcb *GoogleFlowCreateBulk) ExecX(ctx context.Context) {
	if err := gfcb.Exec(ctx); err != nil {
		panic(err)
	}
}
