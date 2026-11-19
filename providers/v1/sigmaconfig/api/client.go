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

// Package api is a minimal, read-only client for the Sigma Config REST API.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Call names, used as the "call" label of the provider's API metrics.
const (
	CallProjectLookup     = "ProjectLookup"
	CallEnvironmentLookup = "EnvironmentLookup"
	CallTagLookup         = "TagLookup"
	CallParameterList     = "ParameterList"
)

const (
	// PageSize is the largest page the API serves.
	PageSize = 1000
	// maxBodyBytes bounds how much of a response is read.
	maxBodyBytes = 64 << 20
	// MaxPages bounds one parameter list: 100 pages of 1,000 is far beyond any real project,
	// and it stops a looping or endless "next" from spending the org's request budget.
	MaxPages = 100
)

var (
	// ErrInsecureServer is returned for a server URL that is not https.
	ErrInsecureServer = errors.New("server must be an https:// URL")
	// ErrUnexpectedNext is returned when a "next" page link points away from the configured server.
	ErrUnexpectedNext = errors.New("pagination link points to a different host")
	// ErrPagination is returned when "next" repeats a page or the list runs past MaxPages.
	ErrPagination = errors.New("parameter list did not end (a page repeated, or more than 100 pages)")
)

// Observer records one API call outcome (wired to metrics.ObserveAPICall by the provider).
type Observer func(call string, err error)

// Options configures a Client.
type Options struct {
	Server     string
	APIKey     string
	UserAgent  string
	HTTPClient *http.Client
	Observe    Observer
	// Sleep waits before the single retry. Tests replace it; nil means a real, context-aware sleep.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client talks to one Sigma Config server with one API key. It only sends GET requests.
type Client struct {
	base    *url.URL
	apiKey  string
	ua      string
	http    *http.Client
	observe Observer
	sleep   func(ctx context.Context, d time.Duration) error
}

// New validates the server URL and returns a Client.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(opts.Server, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, ErrInsecureServer
	}
	c := &Client{
		base:    u,
		apiKey:  opts.APIKey,
		ua:      opts.UserAgent,
		http:    opts.HTTPClient,
		observe: opts.Observe,
		sleep:   opts.Sleep,
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect: Go keeps the Authorization header on a same-host redirect,
	// even from https to http. The 3xx is returned as is and reported as an API error.
	hc := *c.http
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.http = &hc
	if c.observe == nil {
		c.observe = func(string, error) {}
	}
	if c.sleep == nil {
		c.sleep = sleepContext
	}
	return c, nil
}

// ResolveProject returns the ID of the project with exactly this name.
// found is false when the project does not exist or the key cannot see it.
func (c *Client) ResolveProject(ctx context.Context, name string) (id string, found bool, err error) {
	return c.lookupOne(ctx, CallProjectLookup, "/api/v1/projects/", name)
}

// ResolveEnvironment returns the ID of the environment with exactly this name.
func (c *Client) ResolveEnvironment(ctx context.Context, name string) (id string, found bool, err error) {
	return c.lookupOne(ctx, CallEnvironmentLookup, "/api/v1/environments/", name)
}

// TagExists reports whether the environment has a tag with exactly this name.
func (c *Client) TagExists(ctx context.Context, environmentID, tag string) (bool, error) {
	_, found, err := c.lookupOne(ctx, CallTagLookup, "/api/v1/environments/"+url.PathEscape(environmentID)+"/tags/", tag)
	return found, err
}

// ListParameters returns every parameter of the project as seen from the environment,
// optionally at a tag and optionally filtered to one exact name. It follows "next" to the end.
func (c *Client) ListParameters(ctx context.Context, projectID, environment, tag, name string) ([]Parameter, error) {
	q := url.Values{}
	q.Set("environment", environment)
	q.Set("mask_secrets", "false")
	q.Set("page_size", fmt.Sprint(PageSize))
	if tag != "" {
		q.Set("tag", tag)
	}
	if name != "" {
		q.Set("name", name)
	}
	next := c.endpoint("/api/v1/projects/"+url.PathEscape(projectID)+"/parameters/", q)

	var out []Parameter
	seen := map[string]bool{}
	for next != "" {
		if seen[next] || len(seen) >= MaxPages {
			return nil, ErrPagination
		}
		seen[next] = true
		var page listResponse[Parameter]
		if err := c.get(ctx, CallParameterList, next, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Results...)
		next = ""
		if page.Next != nil && *page.Next != "" {
			if err := c.checkSameHost(*page.Next); err != nil {
				return nil, err
			}
			next = *page.Next
		}
	}
	return out, nil
}

func (c *Client) lookupOne(ctx context.Context, call, path, name string) (string, bool, error) {
	q := url.Values{}
	q.Set("name", name)
	var page listResponse[namedObject]
	if err := c.get(ctx, call, c.endpoint(path, q), &page); err != nil {
		return "", false, err
	}
	// name is an exact filter, but check it again rather than trust result order.
	for _, r := range page.Results {
		if r.Name == name {
			return r.ID, true, nil
		}
	}
	return "", false, nil
}

func (c *Client) endpoint(path string, q url.Values) string {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) checkSameHost(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != c.base.Host {
		return ErrUnexpectedNext
	}
	return nil
}

// get performs one GET with a single retry on transient failures, and decodes the JSON body into out.
func (c *Client) get(ctx context.Context, call, rawURL string, out any) error {
	body, err := c.doWithRetry(ctx, call, rawURL)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("sigma config API %s: invalid JSON response", call)
	}
	return nil
}

func (c *Client) doWithRetry(ctx context.Context, call, rawURL string) ([]byte, error) {
	body, err := c.do(ctx, call, rawURL)
	if err == nil || !retryable(ctx, err) {
		return body, err
	}
	// Jitter only spreads retries out; it has no security role.
	jitter := 100*time.Millisecond + time.Duration(rand.Int64N(int64(400*time.Millisecond))) //nolint:gosec // non-security jitter
	if serr := c.sleep(ctx, jitter); serr != nil {
		return nil, err
	}
	return c.do(ctx, call, rawURL)
}

func (c *Client) do(ctx context.Context, call, rawURL string) (body []byte, err error) {
	defer func() { c.observe(call, err) }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("sigma config API %s: building request: %w", call, err)
	}
	req.Header.Set("Authorization", "Api-Key "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)

	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error repeats the URL, which carries no secrets; never wrap the request itself.
		return nil, &transportError{call: call, err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, &transportError{call: call, err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, parseError(call, resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}
	return body, nil
}

// transportError is a connection-level failure (no HTTP response), including timeouts.
type transportError struct {
	call string
	err  error
}

func (e *transportError) Error() string {
	return fmt.Sprintf("sigma config API %s: request failed: %v", e.call, e.err)
}

func (e *transportError) Unwrap() error { return e.err }

// retryable is true for connection errors, timeouts and 502/503/504. Never for any 4xx.
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if _, ok := errors.AsType[*transportError](err); ok {
		return true
	}
	if ae, ok := errors.AsType[*Error](err); ok {
		switch ae.StatusCode {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
	}
	return false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
