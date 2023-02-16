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

package device

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewPostMagicFlowParams creates a new PostMagicFlowParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostMagicFlowParams() *PostMagicFlowParams {
	return &PostMagicFlowParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostMagicFlowParamsWithTimeout creates a new PostMagicFlowParams object
// with the ability to set a timeout on a request.
func NewPostMagicFlowParamsWithTimeout(timeout time.Duration) *PostMagicFlowParams {
	return &PostMagicFlowParams{
		timeout: timeout,
	}
}

// NewPostMagicFlowParamsWithContext creates a new PostMagicFlowParams object
// with the ability to set a context for a request.
func NewPostMagicFlowParamsWithContext(ctx context.Context) *PostMagicFlowParams {
	return &PostMagicFlowParams{
		Context: ctx,
	}
}

// NewPostMagicFlowParamsWithHTTPClient creates a new PostMagicFlowParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostMagicFlowParamsWithHTTPClient(client *http.Client) *PostMagicFlowParams {
	return &PostMagicFlowParams{
		HTTPClient: client,
	}
}

/*
PostMagicFlowParams contains all the parameters to send to the API endpoint

	for the post magic flow operation.

	Typically these are written to a http.Request.
*/
type PostMagicFlowParams struct {

	/* Email.

	   email address
	*/
	Email string

	/* Identifier.

	   Device Flow Identifier
	*/
	Identifier *string

	/* Next.

	   Next Redirect URL
	*/
	Next *string

	/* Organization.

	   Organization
	*/
	Organization *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post magic flow params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostMagicFlowParams) WithDefaults() *PostMagicFlowParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post magic flow params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostMagicFlowParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post magic flow params
func (o *PostMagicFlowParams) WithTimeout(timeout time.Duration) *PostMagicFlowParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post magic flow params
func (o *PostMagicFlowParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post magic flow params
func (o *PostMagicFlowParams) WithContext(ctx context.Context) *PostMagicFlowParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post magic flow params
func (o *PostMagicFlowParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post magic flow params
func (o *PostMagicFlowParams) WithHTTPClient(client *http.Client) *PostMagicFlowParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post magic flow params
func (o *PostMagicFlowParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEmail adds the email to the post magic flow params
func (o *PostMagicFlowParams) WithEmail(email string) *PostMagicFlowParams {
	o.SetEmail(email)
	return o
}

// SetEmail adds the email to the post magic flow params
func (o *PostMagicFlowParams) SetEmail(email string) {
	o.Email = email
}

// WithIdentifier adds the identifier to the post magic flow params
func (o *PostMagicFlowParams) WithIdentifier(identifier *string) *PostMagicFlowParams {
	o.SetIdentifier(identifier)
	return o
}

// SetIdentifier adds the identifier to the post magic flow params
func (o *PostMagicFlowParams) SetIdentifier(identifier *string) {
	o.Identifier = identifier
}

// WithNext adds the next to the post magic flow params
func (o *PostMagicFlowParams) WithNext(next *string) *PostMagicFlowParams {
	o.SetNext(next)
	return o
}

// SetNext adds the next to the post magic flow params
func (o *PostMagicFlowParams) SetNext(next *string) {
	o.Next = next
}

// WithOrganization adds the organization to the post magic flow params
func (o *PostMagicFlowParams) WithOrganization(organization *string) *PostMagicFlowParams {
	o.SetOrganization(organization)
	return o
}

// SetOrganization adds the organization to the post magic flow params
func (o *PostMagicFlowParams) SetOrganization(organization *string) {
	o.Organization = organization
}

// WriteToRequest writes these params to a swagger request
func (o *PostMagicFlowParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param email
	qrEmail := o.Email
	qEmail := qrEmail
	if qEmail != "" {

		if err := r.SetQueryParam("email", qEmail); err != nil {
			return err
		}
	}

	if o.Identifier != nil {

		// query param identifier
		var qrIdentifier string

		if o.Identifier != nil {
			qrIdentifier = *o.Identifier
		}
		qIdentifier := qrIdentifier
		if qIdentifier != "" {

			if err := r.SetQueryParam("identifier", qIdentifier); err != nil {
				return err
			}
		}
	}

	if o.Next != nil {

		// query param next
		var qrNext string

		if o.Next != nil {
			qrNext = *o.Next
		}
		qNext := qrNext
		if qNext != "" {

			if err := r.SetQueryParam("next", qNext); err != nil {
				return err
			}
		}
	}

	if o.Organization != nil {

		// query param organization
		var qrOrganization string

		if o.Organization != nil {
			qrOrganization = *o.Organization
		}
		qOrganization := qrOrganization
		if qOrganization != "" {

			if err := r.SetQueryParam("organization", qOrganization); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}