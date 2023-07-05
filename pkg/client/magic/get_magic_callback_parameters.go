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

package magic

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

// NewGetMagicCallbackParams creates a new GetMagicCallbackParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetMagicCallbackParams() *GetMagicCallbackParams {
	return &GetMagicCallbackParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetMagicCallbackParamsWithTimeout creates a new GetMagicCallbackParams object
// with the ability to set a timeout on a request.
func NewGetMagicCallbackParamsWithTimeout(timeout time.Duration) *GetMagicCallbackParams {
	return &GetMagicCallbackParams{
		timeout: timeout,
	}
}

// NewGetMagicCallbackParamsWithContext creates a new GetMagicCallbackParams object
// with the ability to set a context for a request.
func NewGetMagicCallbackParamsWithContext(ctx context.Context) *GetMagicCallbackParams {
	return &GetMagicCallbackParams{
		Context: ctx,
	}
}

// NewGetMagicCallbackParamsWithHTTPClient creates a new GetMagicCallbackParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetMagicCallbackParamsWithHTTPClient(client *http.Client) *GetMagicCallbackParams {
	return &GetMagicCallbackParams{
		HTTPClient: client,
	}
}

/*
GetMagicCallbackParams contains all the parameters to send to the API endpoint

	for the get magic callback operation.

	Typically these are written to a http.Request.
*/
type GetMagicCallbackParams struct {

	/* Token.

	   magic link token
	*/
	Token string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get magic callback params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetMagicCallbackParams) WithDefaults() *GetMagicCallbackParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get magic callback params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetMagicCallbackParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get magic callback params
func (o *GetMagicCallbackParams) WithTimeout(timeout time.Duration) *GetMagicCallbackParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get magic callback params
func (o *GetMagicCallbackParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get magic callback params
func (o *GetMagicCallbackParams) WithContext(ctx context.Context) *GetMagicCallbackParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get magic callback params
func (o *GetMagicCallbackParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get magic callback params
func (o *GetMagicCallbackParams) WithHTTPClient(client *http.Client) *GetMagicCallbackParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get magic callback params
func (o *GetMagicCallbackParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithToken adds the token to the get magic callback params
func (o *GetMagicCallbackParams) WithToken(token string) *GetMagicCallbackParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the get magic callback params
func (o *GetMagicCallbackParams) SetToken(token string) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *GetMagicCallbackParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param token
	qrToken := o.Token
	qToken := qrToken
	if qToken != "" {

		if err := r.SetQueryParam("token", qToken); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
