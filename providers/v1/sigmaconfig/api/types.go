/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

// listResponse is the envelope every Sigma Config list endpoint returns.
type listResponse[T any] struct {
	Count   int     `json:"count"`
	Next    *string `json:"next"`
	Results []T     `json:"results"`
}

// namedObject is the subset of a project, environment or tag the provider reads.
type namedObject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Parameter is one item of a parameter list response. Unknown fields are ignored.
type Parameter struct {
	Name       string       `json:"name"`
	ValuesFlat []ValueEntry `json:"values_flat"`
}

// ValueEntry is a parameter's value as seen from one environment.
type ValueEntry struct {
	ActiveEnvironmentName string          `json:"active_environment_name"`
	Value                 *string         `json:"value"`
	ExternalStatus        *ExternalStatus `json:"external_status"`
}

// ExternalStatus is set on values pulled from an external store.
type ExternalStatus struct {
	ErrorCode string `json:"error_code"`
}

// ValueFor returns the entry for the requested environment, or nil when there is none.
func (p Parameter) ValueFor(environment string) *ValueEntry {
	for i := range p.ValuesFlat {
		if p.ValuesFlat[i].ActiveEnvironmentName == environment {
			return &p.ValuesFlat[i]
		}
	}
	return nil
}

// Error is a non-2xx response from the Sigma Config API (or the edge in front of it).
// It never holds request headers, the API key or response values.
type Error struct {
	Call       string
	StatusCode int
	// Detail is the "detail" field of a JSON object body.
	Detail string
	// ValidationErrors holds the messages of a JSON list body (template and validation errors).
	ValidationErrors []string
	// NotJSON is true when the body was not JSON, for example an HTML page from the edge.
	NotJSON bool
	// RetryAfter is the Retry-After header of a 429 response.
	RetryAfter string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("sigma config API %s: HTTP %d", e.Call, e.StatusCode)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.RetryAfter != "" {
		msg += " (Retry-After: " + e.RetryAfter + ")"
	}
	return msg
}

// IsTemplateError reports a 400 whose body is a JSON list, which is how the API
// reports templates that fail to evaluate.
func (e *Error) IsTemplateError() bool {
	return e.StatusCode == 400 && e.ValidationErrors != nil
}

// IsEnvironmentNotFound reports a 404 for an unknown environment.
func (e *Error) IsEnvironmentNotFound() bool {
	return e.StatusCode == 404 && strings.HasPrefix(e.Detail, "Environment(s) not found")
}

// IsTagNotFound reports a 404 for an unknown tag.
func (e *Error) IsTagNotFound() bool {
	return e.StatusCode == 404 && strings.HasPrefix(e.Detail, "Tag ")
}

// IsObjectNotFound reports the generic 404 returned for a path whose object no longer exists.
func (e *Error) IsObjectNotFound() bool {
	return e.StatusCode == 404 && e.Detail == "Not found."
}

func parseError(call string, status int, body []byte, retryAfter string) *Error {
	e := &Error{Call: call, StatusCode: status, RetryAfter: retryAfter}
	var obj struct {
		Detail string `json:"detail"`
	}
	var list []string
	switch {
	case json.Unmarshal(body, &obj) == nil:
		e.Detail = obj.Detail
	case json.Unmarshal(body, &list) == nil:
		e.ValidationErrors = list
	default:
		e.NotJSON = true
	}
	return e
}
