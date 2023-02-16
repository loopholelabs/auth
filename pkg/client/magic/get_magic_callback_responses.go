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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// GetMagicCallbackReader is a Reader for the GetMagicCallback structure.
type GetMagicCallbackReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMagicCallbackReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 307:
		result := NewGetMagicCallbackTemporaryRedirect()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetMagicCallbackUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetMagicCallbackForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetMagicCallbackNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetMagicCallbackInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetMagicCallbackTemporaryRedirect creates a GetMagicCallbackTemporaryRedirect with default headers values
func NewGetMagicCallbackTemporaryRedirect() *GetMagicCallbackTemporaryRedirect {
	return &GetMagicCallbackTemporaryRedirect{}
}

/*
GetMagicCallbackTemporaryRedirect describes a response with status code 307, with default header values.

Temporary Redirect
*/
type GetMagicCallbackTemporaryRedirect struct {

	/* Redirects to Next URL
	 */
	Location string
}

// IsSuccess returns true when this get magic callback temporary redirect response has a 2xx status code
func (o *GetMagicCallbackTemporaryRedirect) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get magic callback temporary redirect response has a 3xx status code
func (o *GetMagicCallbackTemporaryRedirect) IsRedirect() bool {
	return true
}

// IsClientError returns true when this get magic callback temporary redirect response has a 4xx status code
func (o *GetMagicCallbackTemporaryRedirect) IsClientError() bool {
	return false
}

// IsServerError returns true when this get magic callback temporary redirect response has a 5xx status code
func (o *GetMagicCallbackTemporaryRedirect) IsServerError() bool {
	return false
}

// IsCode returns true when this get magic callback temporary redirect response a status code equal to that given
func (o *GetMagicCallbackTemporaryRedirect) IsCode(code int) bool {
	return code == 307
}

// Code gets the status code for the get magic callback temporary redirect response
func (o *GetMagicCallbackTemporaryRedirect) Code() int {
	return 307
}

func (o *GetMagicCallbackTemporaryRedirect) Error() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackTemporaryRedirect ", 307)
}

func (o *GetMagicCallbackTemporaryRedirect) String() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackTemporaryRedirect ", 307)
}

func (o *GetMagicCallbackTemporaryRedirect) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Location
	hdrLocation := response.GetHeader("Location")

	if hdrLocation != "" {
		o.Location = hdrLocation
	}

	return nil
}

// NewGetMagicCallbackUnauthorized creates a GetMagicCallbackUnauthorized with default headers values
func NewGetMagicCallbackUnauthorized() *GetMagicCallbackUnauthorized {
	return &GetMagicCallbackUnauthorized{}
}

/*
GetMagicCallbackUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetMagicCallbackUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this get magic callback unauthorized response has a 2xx status code
func (o *GetMagicCallbackUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get magic callback unauthorized response has a 3xx status code
func (o *GetMagicCallbackUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get magic callback unauthorized response has a 4xx status code
func (o *GetMagicCallbackUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get magic callback unauthorized response has a 5xx status code
func (o *GetMagicCallbackUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get magic callback unauthorized response a status code equal to that given
func (o *GetMagicCallbackUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get magic callback unauthorized response
func (o *GetMagicCallbackUnauthorized) Code() int {
	return 401
}

func (o *GetMagicCallbackUnauthorized) Error() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackUnauthorized  %+v", 401, o.Payload)
}

func (o *GetMagicCallbackUnauthorized) String() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackUnauthorized  %+v", 401, o.Payload)
}

func (o *GetMagicCallbackUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *GetMagicCallbackUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMagicCallbackForbidden creates a GetMagicCallbackForbidden with default headers values
func NewGetMagicCallbackForbidden() *GetMagicCallbackForbidden {
	return &GetMagicCallbackForbidden{}
}

/*
GetMagicCallbackForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetMagicCallbackForbidden struct {
	Payload string
}

// IsSuccess returns true when this get magic callback forbidden response has a 2xx status code
func (o *GetMagicCallbackForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get magic callback forbidden response has a 3xx status code
func (o *GetMagicCallbackForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get magic callback forbidden response has a 4xx status code
func (o *GetMagicCallbackForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get magic callback forbidden response has a 5xx status code
func (o *GetMagicCallbackForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get magic callback forbidden response a status code equal to that given
func (o *GetMagicCallbackForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get magic callback forbidden response
func (o *GetMagicCallbackForbidden) Code() int {
	return 403
}

func (o *GetMagicCallbackForbidden) Error() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackForbidden  %+v", 403, o.Payload)
}

func (o *GetMagicCallbackForbidden) String() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackForbidden  %+v", 403, o.Payload)
}

func (o *GetMagicCallbackForbidden) GetPayload() string {
	return o.Payload
}

func (o *GetMagicCallbackForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMagicCallbackNotFound creates a GetMagicCallbackNotFound with default headers values
func NewGetMagicCallbackNotFound() *GetMagicCallbackNotFound {
	return &GetMagicCallbackNotFound{}
}

/*
GetMagicCallbackNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetMagicCallbackNotFound struct {
	Payload string
}

// IsSuccess returns true when this get magic callback not found response has a 2xx status code
func (o *GetMagicCallbackNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get magic callback not found response has a 3xx status code
func (o *GetMagicCallbackNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get magic callback not found response has a 4xx status code
func (o *GetMagicCallbackNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get magic callback not found response has a 5xx status code
func (o *GetMagicCallbackNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get magic callback not found response a status code equal to that given
func (o *GetMagicCallbackNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get magic callback not found response
func (o *GetMagicCallbackNotFound) Code() int {
	return 404
}

func (o *GetMagicCallbackNotFound) Error() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackNotFound  %+v", 404, o.Payload)
}

func (o *GetMagicCallbackNotFound) String() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackNotFound  %+v", 404, o.Payload)
}

func (o *GetMagicCallbackNotFound) GetPayload() string {
	return o.Payload
}

func (o *GetMagicCallbackNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMagicCallbackInternalServerError creates a GetMagicCallbackInternalServerError with default headers values
func NewGetMagicCallbackInternalServerError() *GetMagicCallbackInternalServerError {
	return &GetMagicCallbackInternalServerError{}
}

/*
GetMagicCallbackInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetMagicCallbackInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this get magic callback internal server error response has a 2xx status code
func (o *GetMagicCallbackInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get magic callback internal server error response has a 3xx status code
func (o *GetMagicCallbackInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get magic callback internal server error response has a 4xx status code
func (o *GetMagicCallbackInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get magic callback internal server error response has a 5xx status code
func (o *GetMagicCallbackInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get magic callback internal server error response a status code equal to that given
func (o *GetMagicCallbackInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get magic callback internal server error response
func (o *GetMagicCallbackInternalServerError) Code() int {
	return 500
}

func (o *GetMagicCallbackInternalServerError) Error() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackInternalServerError  %+v", 500, o.Payload)
}

func (o *GetMagicCallbackInternalServerError) String() string {
	return fmt.Sprintf("[GET /magic/callback][%d] getMagicCallbackInternalServerError  %+v", 500, o.Payload)
}

func (o *GetMagicCallbackInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *GetMagicCallbackInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
