// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PolicyAPITestSuite struct{}

var _ = Suite(&PolicyAPITestSuite{})

func (s *PolicyAPITestSuite) TestHTTPEqual(c *C) {
	rule1 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule2 := PortRuleHTTP{Path: "/bar$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule3 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Bar"}}

	c.Assert(rule1.Equal(rule1), Equals, true)
	c.Assert(rule1.Equal(rule2), Equals, false)
	c.Assert(rule1.Equal(rule3), Equals, false)

	rules := L7Rules{
		HTTP: []PortRuleHTTP{rule1, rule2},
	}

	c.Assert(rule1.Exists(rules), Equals, true)
	c.Assert(rule2.Exists(rules), Equals, true)
	c.Assert(rule3.Exists(rules), Equals, false)
}

func (s *PolicyAPITestSuite) TestKafkaEqual(c *C) {
	rule1 := PortRuleKafka{APIVersion: "1", APIKey: "foo", Topic: "topic1"}
	rule2 := PortRuleKafka{APIVersion: "1", APIKey: "bar", Topic: "topic1"}
	rule3 := PortRuleKafka{APIVersion: "1", APIKey: "foo", Topic: "topic2"}

	c.Assert(rule1.Equal(rule1), Equals, true)
	c.Assert(rule1.Equal(rule2), Equals, false)
	c.Assert(rule1.Equal(rule3), Equals, false)

	rules := L7Rules{
		Kafka: []PortRuleKafka{rule1, rule2},
	}

	c.Assert(rule1.Exists(rules), Equals, true)
	c.Assert(rule2.Exists(rules), Equals, true)
	c.Assert(rule3.Exists(rules), Equals, false)
}
