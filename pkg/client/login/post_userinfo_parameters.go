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

package login

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

// NewPostUserinfoParams creates a new PostUserinfoParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostUserinfoParams() *PostUserinfoParams {
	return &PostUserinfoParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostUserinfoParamsWithTimeout creates a new PostUserinfoParams object
// with the ability to set a timeout on a request.
func NewPostUserinfoParamsWithTimeout(timeout time.Duration) *PostUserinfoParams {
	return &PostUserinfoParams{
		timeout: timeout,
	}
}

// NewPostUserinfoParamsWithContext creates a new PostUserinfoParams object
// with the ability to set a context for a request.
func NewPostUserinfoParamsWithContext(ctx context.Context) *PostUserinfoParams {
	return &PostUserinfoParams{
		Context: ctx,
	}
}

// NewPostUserinfoParamsWithHTTPClient creates a new PostUserinfoParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostUserinfoParamsWithHTTPClient(client *http.Client) *PostUserinfoParams {
	return &PostUserinfoParams{
		HTTPClient: client,
	}
}

/*
PostUserinfoParams contains all the parameters to send to the API endpoint

	for the post userinfo operation.

	Typically these are written to a http.Request.
*/
type PostUserinfoParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post userinfo params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostUserinfoParams) WithDefaults() *PostUserinfoParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post userinfo params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostUserinfoParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post userinfo params
func (o *PostUserinfoParams) WithTimeout(timeout time.Duration) *PostUserinfoParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post userinfo params
func (o *PostUserinfoParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post userinfo params
func (o *PostUserinfoParams) WithContext(ctx context.Context) *PostUserinfoParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post userinfo params
func (o *PostUserinfoParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post userinfo params
func (o *PostUserinfoParams) WithHTTPClient(client *http.Client) *PostUserinfoParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post userinfo params
func (o *PostUserinfoParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *PostUserinfoParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
