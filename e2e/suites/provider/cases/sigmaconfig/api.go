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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// apiClient reads expected values straight from Sigma Config, independently of the provider,
// and writes the one scratch value the change-propagation case needs. It never logs a value,
// and its errors carry status codes only.
type apiClient struct {
	server string
	key    string
	http   *http.Client
}

func newAPIClient(server, key string) *apiClient {
	return &apiClient{server: server, key: key, http: &http.Client{Timeout: 30 * time.Second}}
}

type listPage[T any] struct {
	Next    *string `json:"next"`
	Results []T     `json:"results"`
}

type idName struct {
	ID   string `json:"id"`
	URL  string `json:"url"`
	Name string `json:"name"`
}

type parameter struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ValuesFlat []struct {
		ActiveEnvironmentName string  `json:"active_environment_name"`
		Value                 *string `json:"value"`
	} `json:"values_flat"`
}

type value struct {
	ID              string `json:"id"`
	EnvironmentName string `json:"environment_name"`
}

func (c *apiClient) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := c.server + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Api-Key "+c.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "external-secrets-e2e sigmaconfig")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *apiClient) lookup(ctx context.Context, path, name string) (*idName, error) {
	var page listPage[idName]
	if err := c.do(ctx, http.MethodGet, path, url.Values{"name": {name}}, nil, &page); err != nil {
		return nil, err
	}
	for i := range page.Results {
		if page.Results[i].Name == name {
			return &page.Results[i], nil
		}
	}
	return nil, fmt.Errorf("%s %q not found", path, name)
}

// param returns one parameter as seen from an environment, optionally at a tag.
func (c *apiClient) param(ctx context.Context, project, environment, tag, name string) (*parameter, error) {
	p, err := c.lookup(ctx, "/api/v1/projects/", project)
	if err != nil {
		return nil, err
	}
	q := url.Values{"name": {name}, "environment": {environment}, "mask_secrets": {"false"}}
	if tag != "" {
		q.Set("tag", tag)
	}
	var page listPage[parameter]
	if err := c.do(ctx, http.MethodGet, "/api/v1/projects/"+p.ID+"/parameters/", q, nil, &page); err != nil {
		return nil, err
	}
	for i := range page.Results {
		if page.Results[i].Name == name {
			return &page.Results[i], nil
		}
	}
	return nil, fmt.Errorf("parameter %q not found in %s", name, project)
}

// expected returns a parameter's final value in an environment (nil when it has none).
func (c *apiClient) expected(ctx context.Context, project, environment, tag, name string) (*string, error) {
	p, err := c.param(ctx, project, environment, tag, name)
	if err != nil {
		return nil, err
	}
	for _, v := range p.ValuesFlat {
		if v.ActiveEnvironmentName == environment {
			return v.Value, nil
		}
	}
	return nil, nil
}

// setValue writes a parameter's value in one environment, creating the value if it is not set there yet.
func (c *apiClient) setValue(ctx context.Context, project, environment, name, newValue string) error {
	proj, err := c.lookup(ctx, "/api/v1/projects/", project)
	if err != nil {
		return err
	}
	env, err := c.lookup(ctx, "/api/v1/environments/", environment)
	if err != nil {
		return err
	}
	p, err := c.param(ctx, project, environment, "", name)
	if err != nil {
		return err
	}
	valuesPath := "/api/v1/projects/" + proj.ID + "/parameters/" + p.ID + "/values/"
	var page listPage[value]
	if err := c.do(ctx, http.MethodGet, valuesPath, url.Values{"mask_secrets": {"true"}}, nil, &page); err != nil {
		return err
	}
	for _, v := range page.Results {
		if v.EnvironmentName == environment {
			return c.do(ctx, http.MethodPatch, valuesPath+v.ID+"/", nil, map[string]any{"internal_value": newValue}, nil)
		}
	}
	envURL := env.URL
	if envURL == "" {
		envURL = c.server + "/api/v1/environments/" + env.ID + "/"
	}
	return c.do(ctx, http.MethodPost, valuesPath, nil, map[string]any{"environment": envURL, "internal_value": newValue}, nil)
}
