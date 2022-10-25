/*
	Copyright 2022 Loophole Labs

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

package utils

import "time"

// Int64ToTime converts an int64 to a time.Time in a standardized way
func Int64ToTime(i int64) time.Time {
	return time.UnixMilli(i).UTC()
}

// TimeToInt64 converts a time.Time to an int64 in a standardized way
func TimeToInt64(t time.Time) int64 {
	return t.UTC().UnixMilli()
}
