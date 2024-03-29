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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// PostDevicePollReader is a Reader for the PostDevicePoll structure.
type PostDevicePollReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostDevicePollReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostDevicePollOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostDevicePollBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostDevicePollUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPostDevicePollForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPostDevicePollTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostDevicePollInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /device/poll] PostDevicePoll", response, response.Code())
	}
}

// NewPostDevicePollOK creates a PostDevicePollOK with default headers values
func NewPostDevicePollOK() *PostDevicePollOK {
	return &PostDevicePollOK{}
}

/*
PostDevicePollOK describes a response with status code 200, with default header values.

OK
*/
type PostDevicePollOK struct {
	Payload string
}

// IsSuccess returns true when this post device poll o k response has a 2xx status code
func (o *PostDevicePollOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post device poll o k response has a 3xx status code
func (o *PostDevicePollOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device poll o k response has a 4xx status code
func (o *PostDevicePollOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post device poll o k response has a 5xx status code
func (o *PostDevicePollOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post device poll o k response a status code equal to that given
func (o *PostDevicePollOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post device poll o k response
func (o *PostDevicePollOK) Code() int {
	return 200
}

func (o *PostDevicePollOK) Error() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollOK  %+v", 200, o.Payload)
}

func (o *PostDevicePollOK) String() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollOK  %+v", 200, o.Payload)
}

func (o *PostDevicePollOK) GetPayload() string {
	return o.Payload
}

func (o *PostDevicePollOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDevicePollBadRequest creates a PostDevicePollBadRequest with default headers values
func NewPostDevicePollBadRequest() *PostDevicePollBadRequest {
	return &PostDevicePollBadRequest{}
}

/*
PostDevicePollBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostDevicePollBadRequest struct {
	Payload string
}

// IsSuccess returns true when this post device poll bad request response has a 2xx status code
func (o *PostDevicePollBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device poll bad request response has a 3xx status code
func (o *PostDevicePollBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device poll bad request response has a 4xx status code
func (o *PostDevicePollBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post device poll bad request response has a 5xx status code
func (o *PostDevicePollBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post device poll bad request response a status code equal to that given
func (o *PostDevicePollBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post device poll bad request response
func (o *PostDevicePollBadRequest) Code() int {
	return 400
}

func (o *PostDevicePollBadRequest) Error() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollBadRequest  %+v", 400, o.Payload)
}

func (o *PostDevicePollBadRequest) String() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollBadRequest  %+v", 400, o.Payload)
}

func (o *PostDevicePollBadRequest) GetPayload() string {
	return o.Payload
}

func (o *PostDevicePollBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDevicePollUnauthorized creates a PostDevicePollUnauthorized with default headers values
func NewPostDevicePollUnauthorized() *PostDevicePollUnauthorized {
	return &PostDevicePollUnauthorized{}
}

/*
PostDevicePollUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostDevicePollUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post device poll unauthorized response has a 2xx status code
func (o *PostDevicePollUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device poll unauthorized response has a 3xx status code
func (o *PostDevicePollUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device poll unauthorized response has a 4xx status code
func (o *PostDevicePollUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post device poll unauthorized response has a 5xx status code
func (o *PostDevicePollUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post device poll unauthorized response a status code equal to that given
func (o *PostDevicePollUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post device poll unauthorized response
func (o *PostDevicePollUnauthorized) Code() int {
	return 401
}

func (o *PostDevicePollUnauthorized) Error() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollUnauthorized  %+v", 401, o.Payload)
}

func (o *PostDevicePollUnauthorized) String() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollUnauthorized  %+v", 401, o.Payload)
}

func (o *PostDevicePollUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostDevicePollUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDevicePollForbidden creates a PostDevicePollForbidden with default headers values
func NewPostDevicePollForbidden() *PostDevicePollForbidden {
	return &PostDevicePollForbidden{}
}

/*
PostDevicePollForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PostDevicePollForbidden struct {
	Payload string
}

// IsSuccess returns true when this post device poll forbidden response has a 2xx status code
func (o *PostDevicePollForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device poll forbidden response has a 3xx status code
func (o *PostDevicePollForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device poll forbidden response has a 4xx status code
func (o *PostDevicePollForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this post device poll forbidden response has a 5xx status code
func (o *PostDevicePollForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this post device poll forbidden response a status code equal to that given
func (o *PostDevicePollForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the post device poll forbidden response
func (o *PostDevicePollForbidden) Code() int {
	return 403
}

func (o *PostDevicePollForbidden) Error() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollForbidden  %+v", 403, o.Payload)
}

func (o *PostDevicePollForbidden) String() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollForbidden  %+v", 403, o.Payload)
}

func (o *PostDevicePollForbidden) GetPayload() string {
	return o.Payload
}

func (o *PostDevicePollForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDevicePollTooManyRequests creates a PostDevicePollTooManyRequests with default headers values
func NewPostDevicePollTooManyRequests() *PostDevicePollTooManyRequests {
	return &PostDevicePollTooManyRequests{}
}

/*
PostDevicePollTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type PostDevicePollTooManyRequests struct {
	Payload string
}

// IsSuccess returns true when this post device poll too many requests response has a 2xx status code
func (o *PostDevicePollTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device poll too many requests response has a 3xx status code
func (o *PostDevicePollTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device poll too many requests response has a 4xx status code
func (o *PostDevicePollTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this post device poll too many requests response has a 5xx status code
func (o *PostDevicePollTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this post device poll too many requests response a status code equal to that given
func (o *PostDevicePollTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the post device poll too many requests response
func (o *PostDevicePollTooManyRequests) Code() int {
	return 429
}

func (o *PostDevicePollTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollTooManyRequests  %+v", 429, o.Payload)
}

func (o *PostDevicePollTooManyRequests) String() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollTooManyRequests  %+v", 429, o.Payload)
}

func (o *PostDevicePollTooManyRequests) GetPayload() string {
	return o.Payload
}

func (o *PostDevicePollTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDevicePollInternalServerError creates a PostDevicePollInternalServerError with default headers values
func NewPostDevicePollInternalServerError() *PostDevicePollInternalServerError {
	return &PostDevicePollInternalServerError{}
}

/*
PostDevicePollInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostDevicePollInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post device poll internal server error response has a 2xx status code
func (o *PostDevicePollInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device poll internal server error response has a 3xx status code
func (o *PostDevicePollInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device poll internal server error response has a 4xx status code
func (o *PostDevicePollInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post device poll internal server error response has a 5xx status code
func (o *PostDevicePollInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post device poll internal server error response a status code equal to that given
func (o *PostDevicePollInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post device poll internal server error response
func (o *PostDevicePollInternalServerError) Code() int {
	return 500
}

func (o *PostDevicePollInternalServerError) Error() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollInternalServerError  %+v", 500, o.Payload)
}

func (o *PostDevicePollInternalServerError) String() string {
	return fmt.Sprintf("[POST /device/poll][%d] postDevicePollInternalServerError  %+v", 500, o.Payload)
}

func (o *PostDevicePollInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostDevicePollInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
