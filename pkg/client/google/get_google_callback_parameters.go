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

package google

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

// NewGetGoogleCallbackParams creates a new GetGoogleCallbackParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetGoogleCallbackParams() *GetGoogleCallbackParams {
	return &GetGoogleCallbackParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetGoogleCallbackParamsWithTimeout creates a new GetGoogleCallbackParams object
// with the ability to set a timeout on a request.
func NewGetGoogleCallbackParamsWithTimeout(timeout time.Duration) *GetGoogleCallbackParams {
	return &GetGoogleCallbackParams{
		timeout: timeout,
	}
}

// NewGetGoogleCallbackParamsWithContext creates a new GetGoogleCallbackParams object
// with the ability to set a context for a request.
func NewGetGoogleCallbackParamsWithContext(ctx context.Context) *GetGoogleCallbackParams {
	return &GetGoogleCallbackParams{
		Context: ctx,
	}
}

// NewGetGoogleCallbackParamsWithHTTPClient creates a new GetGoogleCallbackParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetGoogleCallbackParamsWithHTTPClient(client *http.Client) *GetGoogleCallbackParams {
	return &GetGoogleCallbackParams{
		HTTPClient: client,
	}
}

/*
GetGoogleCallbackParams contains all the parameters to send to the API endpoint

	for the get google callback operation.

	Typically these are written to a http.Request.
*/
type GetGoogleCallbackParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get google callback params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetGoogleCallbackParams) WithDefaults() *GetGoogleCallbackParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get google callback params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetGoogleCallbackParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get google callback params
func (o *GetGoogleCallbackParams) WithTimeout(timeout time.Duration) *GetGoogleCallbackParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get google callback params
func (o *GetGoogleCallbackParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get google callback params
func (o *GetGoogleCallbackParams) WithContext(ctx context.Context) *GetGoogleCallbackParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get google callback params
func (o *GetGoogleCallbackParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get google callback params
func (o *GetGoogleCallbackParams) WithHTTPClient(client *http.Client) *GetGoogleCallbackParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get google callback params
func (o *GetGoogleCallbackParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetGoogleCallbackParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
