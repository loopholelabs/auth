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

// PostDeviceFlowReader is a Reader for the PostDeviceFlow structure.
type PostDeviceFlowReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostDeviceFlowReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostDeviceFlowOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPostDeviceFlowUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostDeviceFlowInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /device/flow] PostDeviceFlow", response, response.Code())
	}
}

// NewPostDeviceFlowOK creates a PostDeviceFlowOK with default headers values
func NewPostDeviceFlowOK() *PostDeviceFlowOK {
	return &PostDeviceFlowOK{}
}

/*
PostDeviceFlowOK describes a response with status code 200, with default header values.

OK
*/
type PostDeviceFlowOK struct {
	Payload *models.ModelsDeviceFlowResponse
}

// IsSuccess returns true when this post device flow o k response has a 2xx status code
func (o *PostDeviceFlowOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post device flow o k response has a 3xx status code
func (o *PostDeviceFlowOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device flow o k response has a 4xx status code
func (o *PostDeviceFlowOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post device flow o k response has a 5xx status code
func (o *PostDeviceFlowOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post device flow o k response a status code equal to that given
func (o *PostDeviceFlowOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post device flow o k response
func (o *PostDeviceFlowOK) Code() int {
	return 200
}

func (o *PostDeviceFlowOK) Error() string {
	return fmt.Sprintf("[POST /device/flow][%d] postDeviceFlowOK  %+v", 200, o.Payload)
}

func (o *PostDeviceFlowOK) String() string {
	return fmt.Sprintf("[POST /device/flow][%d] postDeviceFlowOK  %+v", 200, o.Payload)
}

func (o *PostDeviceFlowOK) GetPayload() *models.ModelsDeviceFlowResponse {
	return o.Payload
}

func (o *PostDeviceFlowOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ModelsDeviceFlowResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDeviceFlowUnauthorized creates a PostDeviceFlowUnauthorized with default headers values
func NewPostDeviceFlowUnauthorized() *PostDeviceFlowUnauthorized {
	return &PostDeviceFlowUnauthorized{}
}

/*
PostDeviceFlowUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostDeviceFlowUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post device flow unauthorized response has a 2xx status code
func (o *PostDeviceFlowUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device flow unauthorized response has a 3xx status code
func (o *PostDeviceFlowUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device flow unauthorized response has a 4xx status code
func (o *PostDeviceFlowUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post device flow unauthorized response has a 5xx status code
func (o *PostDeviceFlowUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post device flow unauthorized response a status code equal to that given
func (o *PostDeviceFlowUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post device flow unauthorized response
func (o *PostDeviceFlowUnauthorized) Code() int {
	return 401
}

func (o *PostDeviceFlowUnauthorized) Error() string {
	return fmt.Sprintf("[POST /device/flow][%d] postDeviceFlowUnauthorized  %+v", 401, o.Payload)
}

func (o *PostDeviceFlowUnauthorized) String() string {
	return fmt.Sprintf("[POST /device/flow][%d] postDeviceFlowUnauthorized  %+v", 401, o.Payload)
}

func (o *PostDeviceFlowUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostDeviceFlowUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostDeviceFlowInternalServerError creates a PostDeviceFlowInternalServerError with default headers values
func NewPostDeviceFlowInternalServerError() *PostDeviceFlowInternalServerError {
	return &PostDeviceFlowInternalServerError{}
}

/*
PostDeviceFlowInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostDeviceFlowInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post device flow internal server error response has a 2xx status code
func (o *PostDeviceFlowInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post device flow internal server error response has a 3xx status code
func (o *PostDeviceFlowInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post device flow internal server error response has a 4xx status code
func (o *PostDeviceFlowInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post device flow internal server error response has a 5xx status code
func (o *PostDeviceFlowInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post device flow internal server error response a status code equal to that given
func (o *PostDeviceFlowInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post device flow internal server error response
func (o *PostDeviceFlowInternalServerError) Code() int {
	return 500
}

func (o *PostDeviceFlowInternalServerError) Error() string {
	return fmt.Sprintf("[POST /device/flow][%d] postDeviceFlowInternalServerError  %+v", 500, o.Payload)
}

func (o *PostDeviceFlowInternalServerError) String() string {
	return fmt.Sprintf("[POST /device/flow][%d] postDeviceFlowInternalServerError  %+v", 500, o.Payload)
}

func (o *PostDeviceFlowInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostDeviceFlowInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
