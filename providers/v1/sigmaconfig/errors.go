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
	"strings"

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
		retry := "not given"
		if ae.RetryAfter != "" {
			retry = safeToken(ae.RetryAfter)
		}
		return fmt.Errorf("sigmaconfig: the organization's API rate limit is spent (HTTP 429, Retry-After: %s); not retrying now", retry)
	case ae.StatusCode == http.StatusBadRequest && !ae.IsTemplateError():
		// The server's message is left out: a validation message can quote a value.
		return fmt.Errorf("sigmaconfig: %s request rejected (HTTP 400); this is a provider bug, please report it", ae.Call)
	default:
		// Status only. The API's own text is never copied into an error, because it ends up in
		// controller logs and the ExternalSecret status.
		return fmt.Errorf("sigmaconfig: %s returned HTTP %d %s", ae.Call, ae.StatusCode, http.StatusText(ae.StatusCode))
	}
}

// externalPullError reports a value Sigma Config could not pull from an external store.
func externalPullError(name, code string) error {
	return fmt.Errorf("sigmaconfig: parameter %q: its external value could not be pulled (error code %s)", name, safeToken(code))
}

// safeToken passes a short server-supplied token (an error code, a Retry-After value) through
// only if it is plain: letters, digits, space and ".,:-_+". Anything else, or anything long, is
// replaced, so server text cannot inject lines or other content into logs and status.
func safeToken(s string) string {
	const maxLen = 64
	if s == "" || len(s) > maxLen {
		return "(unrecognized)"
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(" .,:-_+", r)
		if !ok {
			return "(unrecognized)"
		}
	}
	return s
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
