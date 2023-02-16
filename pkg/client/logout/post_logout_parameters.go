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

package logout

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

// NewPostLogoutParams creates a new PostLogoutParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostLogoutParams() *PostLogoutParams {
	return &PostLogoutParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostLogoutParamsWithTimeout creates a new PostLogoutParams object
// with the ability to set a timeout on a request.
func NewPostLogoutParamsWithTimeout(timeout time.Duration) *PostLogoutParams {
	return &PostLogoutParams{
		timeout: timeout,
	}
}

// NewPostLogoutParamsWithContext creates a new PostLogoutParams object
// with the ability to set a context for a request.
func NewPostLogoutParamsWithContext(ctx context.Context) *PostLogoutParams {
	return &PostLogoutParams{
		Context: ctx,
	}
}

// NewPostLogoutParamsWithHTTPClient creates a new PostLogoutParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostLogoutParamsWithHTTPClient(client *http.Client) *PostLogoutParams {
	return &PostLogoutParams{
		HTTPClient: client,
	}
}

/*
PostLogoutParams contains all the parameters to send to the API endpoint

	for the post logout operation.

	Typically these are written to a http.Request.
*/
type PostLogoutParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post logout params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostLogoutParams) WithDefaults() *PostLogoutParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post logout params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostLogoutParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post logout params
func (o *PostLogoutParams) WithTimeout(timeout time.Duration) *PostLogoutParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post logout params
func (o *PostLogoutParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post logout params
func (o *PostLogoutParams) WithContext(ctx context.Context) *PostLogoutParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post logout params
func (o *PostLogoutParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post logout params
func (o *PostLogoutParams) WithHTTPClient(client *http.Client) *PostLogoutParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post logout params
func (o *PostLogoutParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *PostLogoutParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
