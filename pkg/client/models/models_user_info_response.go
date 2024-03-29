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

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ModelsUserInfoResponse models user info response
//
// swagger:model models.UserInfoResponse
type ModelsUserInfoResponse struct {

	// identifier
	Identifier string `json:"identifier,omitempty"`

	// kind
	Kind KindKind `json:"kind,omitempty"`

	// organization
	Organization string `json:"organization,omitempty"`
}

// Validate validates this models user info response
func (m *ModelsUserInfoResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateKind(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsUserInfoResponse) validateKind(formats strfmt.Registry) error {
	if swag.IsZero(m.Kind) { // not required
		return nil
	}

	if err := m.Kind.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("kind")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("kind")
		}
		return err
	}

	return nil
}

// ContextValidate validate this models user info response based on the context it is used
func (m *ModelsUserInfoResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateKind(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsUserInfoResponse) contextValidateKind(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Kind) { // not required
		return nil
	}

	if err := m.Kind.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("kind")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("kind")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ModelsUserInfoResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsUserInfoResponse) UnmarshalBinary(b []byte) error {
	var res ModelsUserInfoResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
