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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// All fixture values are fictional.
const (
	testAPIKey    = "fakeprefix.fake-api-key-for-tests"
	testProject   = "payments-api"
	testProjectID = "11111111-1111-1111-1111-111111111111"
	testEnv       = "production"
	testEnvID     = "22222222-2222-2222-2222-222222222222"
)

type fakeParam struct {
	name  string
	value *string // nil = null value
	// byTag holds the value at a tag; a tag missing from the map returns the 404 "Tag ..." error.
	byTag     map[string]*string
	extError  string
	noEnvItem bool // values_flat has no entry for the requested environment
	template  bool // fails to evaluate: bulk reads and by-name reads of it return a 400 JSON list
}

type recorded struct {
	method string
	path   string
	query  url.Values
	header http.Header
}

// fakeAPI plays the parts of the Sigma Config API the provider uses.
type fakeAPI struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	reqs     []recorded
	params   []fakeParam
	projects map[string]string // name -> id
	envs     map[string]string // name -> id
	tags     map[string]bool   // tags of testEnv
	pageSize int               // forces pagination below the client's page_size when > 0
	// override, when set, answers before the default routes. Return false to fall through.
	override func(w http.ResponseWriter, r *http.Request, n int) bool
}

func newFakeAPI(t *testing.T, params ...fakeParam) *fakeAPI {
	t.Helper()
	f := &fakeAPI{
		t:        t,
		params:   params,
		projects: map[string]string{testProject: testProjectID},
		envs:     map[string]string{testEnv: testEnvID, "default": "33333333-3333-3333-3333-333333333333"},
		tags:     map[string]bool{"release-2026-09": true},
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	// Silence handshake errors from tests that check an untrusted server is refused.
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeAPI) count(pathPrefix string) int {
	n := 0
	for _, r := range f.requests() {
		if strings.HasPrefix(r.path, pathPrefix) {
			n++
		}
	}
	return n
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{method: r.Method, path: r.URL.Path, query: r.URL.Query(), header: r.Header.Clone()})
	n := len(f.reqs)
	override := f.override
	f.mu.Unlock()

	if override != nil && override(w, r, n) {
		return
	}
	f.mu.Lock() // tests change projects/params between requests
	defer f.mu.Unlock()
	q := r.URL.Query()
	switch {
	case r.URL.Path == "/api/v1/projects/":
		f.lookup(w, f.projects, q.Get("name"))
	case r.URL.Path == "/api/v1/environments/":
		f.lookup(w, f.envs, q.Get("name"))
	case r.URL.Path == "/api/v1/environments/"+testEnvID+"/tags/":
		ids := map[string]string{}
		for tag := range f.tags {
			ids[tag] = "tag-" + tag
		}
		f.lookup(w, ids, q.Get("name"))
	case strings.HasPrefix(r.URL.Path, "/api/v1/projects/") && strings.HasSuffix(r.URL.Path, "/parameters/"):
		f.parameters(w, r, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/projects/"), "/parameters/"))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not found."})
	}
}

func (f *fakeAPI) lookup(w http.ResponseWriter, objs map[string]string, name string) {
	results := []map[string]string{}
	if id, ok := objs[name]; ok {
		results = append(results, map[string]string{"id": id, "name": name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(results), "next": nil, "previous": nil, "results": results})
}

func (f *fakeAPI) parameters(w http.ResponseWriter, r *http.Request, projectID string) {
	q := r.URL.Query()
	if projectID != f.projects[testProject] || projectID == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not found."})
		return
	}
	env := q.Get("environment")
	if _, ok := f.envs[env]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Environment(s) not found: " + env})
		return
	}
	tag := q.Get("tag")
	if tag != "" && !f.tags[tag] {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": fmt.Sprintf("Tag %#q could not be found in environment %#q.", tag, env)})
		return
	}

	var items []map[string]any
	for _, p := range f.params {
		if name := q.Get("name"); name != "" && p.name != name {
			continue
		}
		if p.template {
			writeJSON(w, http.StatusBadRequest, []string{"Template contains references that do not exist: missing_ref"})
			return
		}
		value := p.value
		if tag != "" {
			value = p.byTag[tag]
		}
		var flat []map[string]any
		if !p.noEnvItem {
			entry := map[string]any{
				"active_environment_name": env,
				"environment_name":        "default",
				"value":                   value,
				"external_status":         nil,
				"evaluated":               false,
				"dynamic":                 true, // undocumented field: must be ignored
			}
			if p.extError != "" {
				entry["external_status"] = map[string]string{"error_code": p.extError, "error_detail": "fictional"}
			}
			flat = append(flat, entry)
		}
		items = append(items, map[string]any{"name": p.name, "secret": true, "type": "string", "static_value": "x", "values_flat": flat})
	}

	pageSize := len(items)
	if f.pageSize > 0 {
		pageSize = f.pageSize
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	start := min((page-1)*pageSize, len(items))
	end := min(start+pageSize, len(items))
	var next any
	if end < len(items) {
		nq := r.URL.Query()
		nq.Set("page", strconv.Itoa(page+1))
		next = f.srv.URL + r.URL.Path + "?" + nq.Encode()
	}
	results := items[start:end]
	if results == nil {
		results = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(items), "next": next, "previous": nil, "results": results})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeHTML(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<html><body>blocked</body></html>"))
}

// fakeClock drives cache expiry without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type testEnvCaches struct {
	clock      *fakeClock
	snapshots  *snapshotCache
	projectIDs *projectIDCache
}

func newTestCaches() *testEnvCaches {
	clock := &fakeClock{now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	return &testEnvCaches{clock: clock, snapshots: newSnapshotCache(clock.Now), projectIDs: &projectIDCache{}}
}

func testSpec(mutate func(*esv1.SigmaConfigProvider)) *esv1.SigmaConfigProvider {
	spec := &esv1.SigmaConfigProvider{
		Project:     testProject,
		Environment: testEnv,
		Auth: esv1.SigmaConfigAuth{
			APIKeySecretRef: esmeta.SecretKeySelector{Name: "sigma-config-api-key", Key: "api-key"},
		},
	}
	if mutate != nil {
		mutate(spec)
	}
	return spec
}

// newTestClient builds a client against the fake, with its own caches and an instant retry sleep.
func newTestClient(t *testing.T, f *fakeAPI, caches *testEnvCaches, mutate func(*esv1.SigmaConfigProvider)) *secretsClient {
	t.Helper()
	spec := testSpec(func(s *esv1.SigmaConfigProvider) {
		s.Server = f.srv.URL
		if mutate != nil {
			mutate(s)
		}
	})
	c, err := newClient(spec, testAPIKey, f.srv.Client(), func(context.Context, time.Duration) error { return nil })
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	c.snapshots = caches.snapshots
	c.projectIDs = caches.projectIDs
	return c
}
