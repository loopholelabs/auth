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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// PostLogoutReader is a Reader for the PostLogout structure.
type PostLogoutReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostLogoutReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostLogoutOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostLogoutBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostLogoutUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostLogoutInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /logout] PostLogout", response, response.Code())
	}
}

// NewPostLogoutOK creates a PostLogoutOK with default headers values
func NewPostLogoutOK() *PostLogoutOK {
	return &PostLogoutOK{}
}

/*
PostLogoutOK describes a response with status code 200, with default header values.

OK
*/
type PostLogoutOK struct {
	Payload string
}

// IsSuccess returns true when this post logout o k response has a 2xx status code
func (o *PostLogoutOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post logout o k response has a 3xx status code
func (o *PostLogoutOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post logout o k response has a 4xx status code
func (o *PostLogoutOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post logout o k response has a 5xx status code
func (o *PostLogoutOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post logout o k response a status code equal to that given
func (o *PostLogoutOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post logout o k response
func (o *PostLogoutOK) Code() int {
	return 200
}

func (o *PostLogoutOK) Error() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutOK  %+v", 200, o.Payload)
}

func (o *PostLogoutOK) String() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutOK  %+v", 200, o.Payload)
}

func (o *PostLogoutOK) GetPayload() string {
	return o.Payload
}

func (o *PostLogoutOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostLogoutBadRequest creates a PostLogoutBadRequest with default headers values
func NewPostLogoutBadRequest() *PostLogoutBadRequest {
	return &PostLogoutBadRequest{}
}

/*
PostLogoutBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostLogoutBadRequest struct {
	Payload string
}

// IsSuccess returns true when this post logout bad request response has a 2xx status code
func (o *PostLogoutBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post logout bad request response has a 3xx status code
func (o *PostLogoutBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post logout bad request response has a 4xx status code
func (o *PostLogoutBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post logout bad request response has a 5xx status code
func (o *PostLogoutBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post logout bad request response a status code equal to that given
func (o *PostLogoutBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post logout bad request response
func (o *PostLogoutBadRequest) Code() int {
	return 400
}

func (o *PostLogoutBadRequest) Error() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutBadRequest  %+v", 400, o.Payload)
}

func (o *PostLogoutBadRequest) String() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutBadRequest  %+v", 400, o.Payload)
}

func (o *PostLogoutBadRequest) GetPayload() string {
	return o.Payload
}

func (o *PostLogoutBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostLogoutUnauthorized creates a PostLogoutUnauthorized with default headers values
func NewPostLogoutUnauthorized() *PostLogoutUnauthorized {
	return &PostLogoutUnauthorized{}
}

/*
PostLogoutUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostLogoutUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post logout unauthorized response has a 2xx status code
func (o *PostLogoutUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post logout unauthorized response has a 3xx status code
func (o *PostLogoutUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post logout unauthorized response has a 4xx status code
func (o *PostLogoutUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post logout unauthorized response has a 5xx status code
func (o *PostLogoutUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post logout unauthorized response a status code equal to that given
func (o *PostLogoutUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post logout unauthorized response
func (o *PostLogoutUnauthorized) Code() int {
	return 401
}

func (o *PostLogoutUnauthorized) Error() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutUnauthorized  %+v", 401, o.Payload)
}

func (o *PostLogoutUnauthorized) String() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutUnauthorized  %+v", 401, o.Payload)
}

func (o *PostLogoutUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostLogoutUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostLogoutInternalServerError creates a PostLogoutInternalServerError with default headers values
func NewPostLogoutInternalServerError() *PostLogoutInternalServerError {
	return &PostLogoutInternalServerError{}
}

/*
PostLogoutInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostLogoutInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post logout internal server error response has a 2xx status code
func (o *PostLogoutInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post logout internal server error response has a 3xx status code
func (o *PostLogoutInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post logout internal server error response has a 4xx status code
func (o *PostLogoutInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post logout internal server error response has a 5xx status code
func (o *PostLogoutInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post logout internal server error response a status code equal to that given
func (o *PostLogoutInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post logout internal server error response
func (o *PostLogoutInternalServerError) Code() int {
	return 500
}

func (o *PostLogoutInternalServerError) Error() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutInternalServerError  %+v", 500, o.Payload)
}

func (o *PostLogoutInternalServerError) String() string {
	return fmt.Sprintf("[POST /logout][%d] postLogoutInternalServerError  %+v", 500, o.Payload)
}

func (o *PostLogoutInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostLogoutInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
