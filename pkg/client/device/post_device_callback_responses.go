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

	"github.com/loopholelabs/auth/pkg/client/models"
)

// PostDeviceCallbackReader is a Reader for the PostDeviceCallback structure.
type PostDeviceCallbackReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostDeviceCallbackReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostDeviceCallbackOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostDeviceCallbackBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostDeviceCallbackUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostDeviceCallbackInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /device/callback] PostDeviceCallback", response, response.Code())
	}
}

// NewPostDeviceCallbackOK creates a PostDeviceCallbackOK with default headers values
func NewPostDeviceCallbackOK() *PostDeviceCallbackOK {
	return &PostDeviceCallbackOK{}
}

/*
PostDeviceCallbackOK describes a response with status code 200, with default header values.

OK
*/
type PostDeviceCallbackOK struct {
	Payload *models.ModelsDeviceCallbackResponse
}

// IsSuccess returns true when this post device callback o k response has a 2xx status code
func (o *PostDeviceCallbackOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post device callback o k response has a 3xx status code
func (o *PostDeviceCallbackOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device callback o k response has a 4xx status code
func (o *PostDeviceCallbackOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post device callback o k response has a 5xx status code
func (o *PostDeviceCallbackOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post device callback o k response a status code equal to that given
func (o *PostDeviceCallbackOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post device callback o k response
func (o *PostDeviceCallbackOK) Code() int {
	return 200
}

func (o *PostDeviceCallbackOK) Error() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackOK  %+v", 200, o.Payload)
}

func (o *PostDeviceCallbackOK) String() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackOK  %+v", 200, o.Payload)
}

func (o *PostDeviceCallbackOK) GetPayload() *models.ModelsDeviceCallbackResponse {
	return o.Payload
}

func (o *PostDeviceCallbackOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ModelsDeviceCallbackResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDeviceCallbackBadRequest creates a PostDeviceCallbackBadRequest with default headers values
func NewPostDeviceCallbackBadRequest() *PostDeviceCallbackBadRequest {
	return &PostDeviceCallbackBadRequest{}
}

/*
PostDeviceCallbackBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostDeviceCallbackBadRequest struct {
	Payload string
}

// IsSuccess returns true when this post device callback bad request response has a 2xx status code
func (o *PostDeviceCallbackBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device callback bad request response has a 3xx status code
func (o *PostDeviceCallbackBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device callback bad request response has a 4xx status code
func (o *PostDeviceCallbackBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post device callback bad request response has a 5xx status code
func (o *PostDeviceCallbackBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post device callback bad request response a status code equal to that given
func (o *PostDeviceCallbackBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post device callback bad request response
func (o *PostDeviceCallbackBadRequest) Code() int {
	return 400
}

func (o *PostDeviceCallbackBadRequest) Error() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackBadRequest  %+v", 400, o.Payload)
}

func (o *PostDeviceCallbackBadRequest) String() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackBadRequest  %+v", 400, o.Payload)
}

func (o *PostDeviceCallbackBadRequest) GetPayload() string {
	return o.Payload
}

func (o *PostDeviceCallbackBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDeviceCallbackUnauthorized creates a PostDeviceCallbackUnauthorized with default headers values
func NewPostDeviceCallbackUnauthorized() *PostDeviceCallbackUnauthorized {
	return &PostDeviceCallbackUnauthorized{}
}

/*
PostDeviceCallbackUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostDeviceCallbackUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post device callback unauthorized response has a 2xx status code
func (o *PostDeviceCallbackUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device callback unauthorized response has a 3xx status code
func (o *PostDeviceCallbackUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device callback unauthorized response has a 4xx status code
func (o *PostDeviceCallbackUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post device callback unauthorized response has a 5xx status code
func (o *PostDeviceCallbackUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post device callback unauthorized response a status code equal to that given
func (o *PostDeviceCallbackUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post device callback unauthorized response
func (o *PostDeviceCallbackUnauthorized) Code() int {
	return 401
}

func (o *PostDeviceCallbackUnauthorized) Error() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackUnauthorized  %+v", 401, o.Payload)
}

func (o *PostDeviceCallbackUnauthorized) String() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackUnauthorized  %+v", 401, o.Payload)
}

func (o *PostDeviceCallbackUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostDeviceCallbackUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDeviceCallbackInternalServerError creates a PostDeviceCallbackInternalServerError with default headers values
func NewPostDeviceCallbackInternalServerError() *PostDeviceCallbackInternalServerError {
	return &PostDeviceCallbackInternalServerError{}
}

/*
PostDeviceCallbackInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostDeviceCallbackInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post device callback internal server error response has a 2xx status code
func (o *PostDeviceCallbackInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device callback internal server error response has a 3xx status code
func (o *PostDeviceCallbackInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device callback internal server error response has a 4xx status code
func (o *PostDeviceCallbackInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post device callback internal server error response has a 5xx status code
func (o *PostDeviceCallbackInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post device callback internal server error response a status code equal to that given
func (o *PostDeviceCallbackInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post device callback internal server error response
func (o *PostDeviceCallbackInternalServerError) Code() int {
	return 500
}

func (o *PostDeviceCallbackInternalServerError) Error() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackInternalServerError  %+v", 500, o.Payload)
}

func (o *PostDeviceCallbackInternalServerError) String() string {
	return fmt.Sprintf("[POST /device/callback][%d] postDeviceCallbackInternalServerError  %+v", 500, o.Payload)
}

func (o *PostDeviceCallbackInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostDeviceCallbackInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
