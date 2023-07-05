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

package github

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// GetGithubLoginReader is a Reader for the GetGithubLogin structure.
type GetGithubLoginReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetGithubLoginReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 307:
		result := NewGetGithubLoginTemporaryRedirect()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetGithubLoginUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetGithubLoginInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /github/login] GetGithubLogin", response, response.Code())
	}
}

// NewGetGithubLoginTemporaryRedirect creates a GetGithubLoginTemporaryRedirect with default headers values
func NewGetGithubLoginTemporaryRedirect() *GetGithubLoginTemporaryRedirect {
	return &GetGithubLoginTemporaryRedirect{}
}

/*
GetGithubLoginTemporaryRedirect describes a response with status code 307, with default header values.

Temporary Redirect
*/
type GetGithubLoginTemporaryRedirect struct {

	/* Redirects to Github
	 */
	Location string
}

// IsSuccess returns true when this get github login temporary redirect response has a 2xx status code
func (o *GetGithubLoginTemporaryRedirect) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get github login temporary redirect response has a 3xx status code
func (o *GetGithubLoginTemporaryRedirect) IsRedirect() bool {
	return true
}

// IsClientError returns true when this get github login temporary redirect response has a 4xx status code
func (o *GetGithubLoginTemporaryRedirect) IsClientError() bool {
	return false
}

// IsServerError returns true when this get github login temporary redirect response has a 5xx status code
func (o *GetGithubLoginTemporaryRedirect) IsServerError() bool {
	return false
}

// IsCode returns true when this get github login temporary redirect response a status code equal to that given
func (o *GetGithubLoginTemporaryRedirect) IsCode(code int) bool {
	return code == 307
}

// Code gets the status code for the get github login temporary redirect response
func (o *GetGithubLoginTemporaryRedirect) Code() int {
	return 307
}

func (o *GetGithubLoginTemporaryRedirect) Error() string {
	return fmt.Sprintf("[GET /github/login][%d] getGithubLoginTemporaryRedirect ", 307)
}

func (o *GetGithubLoginTemporaryRedirect) String() string {
	return fmt.Sprintf("[GET /github/login][%d] getGithubLoginTemporaryRedirect ", 307)
}

func (o *GetGithubLoginTemporaryRedirect) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Location
	hdrLocation := response.GetHeader("Location")

	if hdrLocation != "" {
		o.Location = hdrLocation
	}

	return nil
}

// NewGetGithubLoginUnauthorized creates a GetGithubLoginUnauthorized with default headers values
func NewGetGithubLoginUnauthorized() *GetGithubLoginUnauthorized {
	return &GetGithubLoginUnauthorized{}
}

/*
GetGithubLoginUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetGithubLoginUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this get github login unauthorized response has a 2xx status code
func (o *GetGithubLoginUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get github login unauthorized response has a 3xx status code
func (o *GetGithubLoginUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get github login unauthorized response has a 4xx status code
func (o *GetGithubLoginUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get github login unauthorized response has a 5xx status code
func (o *GetGithubLoginUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get github login unauthorized response a status code equal to that given
func (o *GetGithubLoginUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get github login unauthorized response
func (o *GetGithubLoginUnauthorized) Code() int {
	return 401
}

func (o *GetGithubLoginUnauthorized) Error() string {
	return fmt.Sprintf("[GET /github/login][%d] getGithubLoginUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGithubLoginUnauthorized) String() string {
	return fmt.Sprintf("[GET /github/login][%d] getGithubLoginUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGithubLoginUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *GetGithubLoginUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGithubLoginInternalServerError creates a GetGithubLoginInternalServerError with default headers values
func NewGetGithubLoginInternalServerError() *GetGithubLoginInternalServerError {
	return &GetGithubLoginInternalServerError{}
}

/*
GetGithubLoginInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetGithubLoginInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this get github login internal server error response has a 2xx status code
func (o *GetGithubLoginInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get github login internal server error response has a 3xx status code
func (o *GetGithubLoginInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get github login internal server error response has a 4xx status code
func (o *GetGithubLoginInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get github login internal server error response has a 5xx status code
func (o *GetGithubLoginInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get github login internal server error response a status code equal to that given
func (o *GetGithubLoginInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get github login internal server error response
func (o *GetGithubLoginInternalServerError) Code() int {
	return 500
}

func (o *GetGithubLoginInternalServerError) Error() string {
	return fmt.Sprintf("[GET /github/login][%d] getGithubLoginInternalServerError  %+v", 500, o.Payload)
}

func (o *GetGithubLoginInternalServerError) String() string {
	return fmt.Sprintf("[GET /github/login][%d] getGithubLoginInternalServerError  %+v", 500, o.Payload)
}

func (o *GetGithubLoginInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *GetGithubLoginInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
