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

// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// KindKind kind kind
//
// swagger:model kind.Kind
type KindKind string

func NewKindKind(value KindKind) *KindKind {
	return &value
}

// Pointer returns a pointer to a freshly-allocated KindKind.
func (m KindKind) Pointer() *KindKind {
	return &m
}

const (

	// KindKindSession captures enum value "session"
	KindKindSession KindKind = "session"

	// KindKindAPI captures enum value "api"
	KindKindAPI KindKind = "api"

	// KindKindService captures enum value "service"
	KindKindService KindKind = "service"
)

// for schema
var kindKindEnum []interface{}

func init() {
	var res []KindKind
	if err := json.Unmarshal([]byte(`["session","api","service"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		kindKindEnum = append(kindKindEnum, v)
	}
}

func (m KindKind) validateKindKindEnum(path, location string, value KindKind) error {
	if err := validate.EnumCase(path, location, value, kindKindEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this kind kind
func (m KindKind) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateKindKindEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this kind kind based on context it is used
func (m KindKind) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
