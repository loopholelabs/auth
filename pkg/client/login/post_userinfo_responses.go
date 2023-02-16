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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/loopholelabs/auth/pkg/client/models"
)

// PostUserinfoReader is a Reader for the PostUserinfo structure.
type PostUserinfoReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostUserinfoReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostUserinfoOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostUserinfoBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostUserinfoUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostUserinfoInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostUserinfoOK creates a PostUserinfoOK with default headers values
func NewPostUserinfoOK() *PostUserinfoOK {
	return &PostUserinfoOK{}
}

/*
PostUserinfoOK describes a response with status code 200, with default header values.

OK
*/
type PostUserinfoOK struct {
	Payload *models.ModelsUserInfoResponse
}

// IsSuccess returns true when this post userinfo o k response has a 2xx status code
func (o *PostUserinfoOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post userinfo o k response has a 3xx status code
func (o *PostUserinfoOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userinfo o k response has a 4xx status code
func (o *PostUserinfoOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post userinfo o k response has a 5xx status code
func (o *PostUserinfoOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post userinfo o k response a status code equal to that given
func (o *PostUserinfoOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post userinfo o k response
func (o *PostUserinfoOK) Code() int {
	return 200
}

func (o *PostUserinfoOK) Error() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoOK  %+v", 200, o.Payload)
}

func (o *PostUserinfoOK) String() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoOK  %+v", 200, o.Payload)
}

func (o *PostUserinfoOK) GetPayload() *models.ModelsUserInfoResponse {
	return o.Payload
}

func (o *PostUserinfoOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ModelsUserInfoResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserinfoBadRequest creates a PostUserinfoBadRequest with default headers values
func NewPostUserinfoBadRequest() *PostUserinfoBadRequest {
	return &PostUserinfoBadRequest{}
}

/*
PostUserinfoBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostUserinfoBadRequest struct {
	Payload string
}

// IsSuccess returns true when this post userinfo bad request response has a 2xx status code
func (o *PostUserinfoBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userinfo bad request response has a 3xx status code
func (o *PostUserinfoBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userinfo bad request response has a 4xx status code
func (o *PostUserinfoBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userinfo bad request response has a 5xx status code
func (o *PostUserinfoBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post userinfo bad request response a status code equal to that given
func (o *PostUserinfoBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post userinfo bad request response
func (o *PostUserinfoBadRequest) Code() int {
	return 400
}

func (o *PostUserinfoBadRequest) Error() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoBadRequest  %+v", 400, o.Payload)
}

func (o *PostUserinfoBadRequest) String() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoBadRequest  %+v", 400, o.Payload)
}

func (o *PostUserinfoBadRequest) GetPayload() string {
	return o.Payload
}

func (o *PostUserinfoBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserinfoUnauthorized creates a PostUserinfoUnauthorized with default headers values
func NewPostUserinfoUnauthorized() *PostUserinfoUnauthorized {
	return &PostUserinfoUnauthorized{}
}

/*
PostUserinfoUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostUserinfoUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post userinfo unauthorized response has a 2xx status code
func (o *PostUserinfoUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userinfo unauthorized response has a 3xx status code
func (o *PostUserinfoUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userinfo unauthorized response has a 4xx status code
func (o *PostUserinfoUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userinfo unauthorized response has a 5xx status code
func (o *PostUserinfoUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post userinfo unauthorized response a status code equal to that given
func (o *PostUserinfoUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post userinfo unauthorized response
func (o *PostUserinfoUnauthorized) Code() int {
	return 401
}

func (o *PostUserinfoUnauthorized) Error() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoUnauthorized  %+v", 401, o.Payload)
}

func (o *PostUserinfoUnauthorized) String() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoUnauthorized  %+v", 401, o.Payload)
}

func (o *PostUserinfoUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostUserinfoUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserinfoInternalServerError creates a PostUserinfoInternalServerError with default headers values
func NewPostUserinfoInternalServerError() *PostUserinfoInternalServerError {
	return &PostUserinfoInternalServerError{}
}

/*
PostUserinfoInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostUserinfoInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post userinfo internal server error response has a 2xx status code
func (o *PostUserinfoInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userinfo internal server error response has a 3xx status code
func (o *PostUserinfoInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userinfo internal server error response has a 4xx status code
func (o *PostUserinfoInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post userinfo internal server error response has a 5xx status code
func (o *PostUserinfoInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post userinfo internal server error response a status code equal to that given
func (o *PostUserinfoInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post userinfo internal server error response
func (o *PostUserinfoInternalServerError) Code() int {
	return 500
}

func (o *PostUserinfoInternalServerError) Error() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoInternalServerError  %+v", 500, o.Payload)
}

func (o *PostUserinfoInternalServerError) String() string {
	return fmt.Sprintf("[POST /userinfo][%d] postUserinfoInternalServerError  %+v", 500, o.Payload)
}

func (o *PostUserinfoInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostUserinfoInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
