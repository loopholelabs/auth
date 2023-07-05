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

package storage

// HealthErrors contains errors that may have occurred while checking the health of the storage implementation.
type HealthErrors struct {
	RegistrationError   error
	SecretKeyError      error
	APIKeyError         error
	ServiceSessionError error
	SessionError        error
}

// Health is meant to be implemented by the storage to check the status of the storage implementation.
type Health interface {
	// Errors returns the errors that may have occurred while checking the health of the storage implementation.
	//
	// The returned HealthErrors cannot be nil, and if there are no errors the HealthErrors should contain
	// nil values for each error.
	Errors() HealthErrors
}
