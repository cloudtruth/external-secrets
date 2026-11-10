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

package sigmaconfig

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/external-secrets/external-secrets/providers/v1/sigmaconfig/api"
)

var (
	errReadOnly          = errors.New("sigmaconfig provider is read-only")
	errProjectNotVisible = errors.New("project not found or not visible to this API key (check the name, and the service account's grants if the project is access-controlled)")
	errBlockedAtEdge     = errors.New("request blocked before reaching Sigma Config (HTTP 403 from the edge, usually the per-IP rate limit); it will be retried on the next reconcile")
)

// describe turns an API error into a message for the store or ExternalSecret status.
// Messages may name the project, environment, tag, parameter and key selector, but never
// the API key or any value.
func (c *secretsClient) describe(err error, tag string) error {
	var ae *api.Error
	if !errors.As(err, &ae) {
		return fmt.Errorf("sigmaconfig: %w", err)
	}
	switch {
	case ae.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("sigmaconfig: authentication failed (HTTP 401): check the API key in Secret %q, key %q", c.keyRef.Name, c.keyRef.Key)
	case ae.StatusCode == http.StatusForbidden && ae.NotJSON:
		return errBlockedAtEdge
	case ae.StatusCode == http.StatusForbidden:
		return fmt.Errorf("sigmaconfig: permission denied (HTTP 403) for project %q: check the service account's role and grants", c.project)
	case ae.IsEnvironmentNotFound():
		return fmt.Errorf("sigmaconfig: environment %q not found", c.environment)
	case ae.IsTagNotFound():
		return fmt.Errorf("sigmaconfig: tag %q not found in environment %q", tag, c.environment)
	case ae.StatusCode == http.StatusTooManyRequests:
		retry := ae.RetryAfter
		if retry == "" {
			retry = "not given"
		}
		return fmt.Errorf("sigmaconfig: the organization's API rate limit is spent (HTTP 429, Retry-After: %s); not retrying now", retry)
	case ae.StatusCode == http.StatusBadRequest && !ae.IsTemplateError():
		return fmt.Errorf("sigmaconfig: request rejected (HTTP 400: %s); this is a provider bug, please report it", ae.Detail)
	case ae.NotJSON:
		return fmt.Errorf("sigmaconfig: %s returned HTTP %d %s", ae.Call, ae.StatusCode, http.StatusText(ae.StatusCode))
	default:
		return fmt.Errorf("sigmaconfig: %w", ae)
	}
}

// templateError reports a parameter whose template fails to evaluate. The API's messages are
// left out on purpose: a type or rule failure can quote the rendered value.
func templateError(project, environment, name string) error {
	return fmt.Errorf(
		"sigmaconfig: parameter %q in project %q, environment %q: its value failed to evaluate in Sigma Config (template or validation error); fix it in Sigma Config",
		name,
		project,
		environment,
	)
}

func isTemplateError(err error) bool {
	var ae *api.Error
	return errors.As(err, &ae) && ae.IsTemplateError()
}
