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
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestAudience(t *testing.T) {
	a := Audience{"a", "b"}
	sa := Audience{"single"}

	b, err := json.Marshal(a)
	assert.NoError(t, err)

	bt, err := a.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, b, bt)

	sb, err := json.Marshal(sa)
	assert.NoError(t, err)

	sbt, err := sa.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, sb, sbt)

	var ta Audience
	err = json.Unmarshal(b, &ta)
	assert.NoError(t, err)
	assert.Equal(t, a, ta)

	var tsa Audience
	err = json.Unmarshal(sb, &tsa)
	assert.NoError(t, err)
	assert.Equal(t, sa, tsa)
}

func TestTime(t *testing.T) {
	ti := Time(time.UnixMilli(time.Now().UnixMilli()))
	bti, err := ti.MarshalJSON()
	assert.NoError(t, err)

	var tt Time
	err = tt.UnmarshalJSON(bti)
	assert.NoError(t, err)
	assert.True(t, time.Time(tt).Equal(time.Time(ti)))

	bti, err = json.Marshal(ti)
	assert.NoError(t, err)

	err = json.Unmarshal(bti, &tt)
	assert.NoError(t, err)
	assert.True(t, time.Time(tt).Equal(time.Time(ti)))
}
