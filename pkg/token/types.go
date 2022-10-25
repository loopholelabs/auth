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

package token

import (
	"encoding/json"
	"github.com/loopholelabs/auth/pkg/utils"
	"time"
)

var _ json.Marshaler = (*Time)(nil)
var _ json.Marshaler = Time{}
var _ json.Unmarshaler = (*Time)(nil)

var _ json.Marshaler = (*Audience)(nil)
var _ json.Marshaler = Audience{}
var _ json.Unmarshaler = (*Audience)(nil)

type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal((a)[0])
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(bytes []byte) error {
	var s string
	if json.Unmarshal(bytes, &s) == nil {
		*a = Audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(bytes, &auds); err != nil {
		return err
	}
	*a = auds
	return nil
}

type Time time.Time

func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(utils.TimeToInt64(time.Time(t)))
}

func (t *Time) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*t = Time(utils.Int64ToTime(unix))
	return nil
}
