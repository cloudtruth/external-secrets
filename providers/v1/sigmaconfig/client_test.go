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
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

const (
	dbPassword  = "fictional-db-password"
	stripeValue = `{"secret_key":"fictional-sk","publishable_key":"fictional-pk","limits":{"daily":5}}`
)

func defaultParams() []fakeParam {
	return []fakeParam{
		{name: "db_password", value: new(dbPassword)},
		{name: "stripe", value: new(stripeValue)},
		{name: "max_connections", value: new("25")},
		{name: "feature_flags", value: new("new"), byTag: map[string]*string{"release-2026-09": new("old")}},
		{name: "dev_only", value: nil},
		{name: "not_in_env", noEnvItem: true},
		{name: "aws_pulled", value: new("stale"), extError: "AccessDenied"},
	}
}

func get(t *testing.T, c *secretsClient, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	t.Helper()
	return c.GetSecret(context.Background(), ref)
}

// --- 2.1 Request shape ---

func TestRequestShape(t *testing.T) {
	f := newFakeAPI(t, defaultParams()...)
	c := newTestClient(t, f, newTestCaches(), nil)
	if _, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	reqs := f.requests()
	if len(reqs) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, r := range reqs {
		if r.method != http.MethodGet { // U-03
			t.Errorf("non-GET request: %s %s", r.method, r.path)
		}
		if got := r.header.Get("Authorization"); got != "Api-Key "+testAPIKey { // U-01
			t.Errorf("Authorization header = %q", got)
		}
		ua := r.header.Get("User-Agent") // U-02
		if !strings.HasPrefix(ua, "external-secrets/") || !strings.HasSuffix(ua, " sigmaconfig-provider") {
			t.Errorf("User-Agent = %q", ua)
		}
		for _, banned := range []string{"values", "as_of", "immediate_parameters"} { // U-06
			if r.query.Has(banned) {
				t.Errorf("%s sent %q", r.path, banned)
			}
		}
		if strings.HasSuffix(r.path, "/parameters/") {
			if r.query.Get("mask_secrets") != "false" { // U-04
				t.Errorf("mask_secrets = %q", r.query.Get("mask_secrets"))
			}
			if r.query.Get("environment") != testEnv || r.query.Get("page_size") != "1000" { // U-05
				t.Errorf("parameter query = %v", r.query)
			}
			if r.path != "/api/v1/projects/"+testProjectID+"/parameters/" { // U-08
				t.Errorf("parameters path = %s", r.path)
			}
		}
	}
	if f.count("/api/v1/projects/") == 0 || reqs[0].path != "/api/v1/projects/" || reqs[0].query.Get("name") != testProject { // U-08
		t.Errorf("first request should resolve the project by name, got %s?%s", reqs[0].path, reqs[0].query.Encode())
	}
}

func TestTagQuery(t *testing.T) { // U-07
	f := newFakeAPI(t, defaultParams()...)
	c := newTestClient(t, f, newTestCaches(), func(s *esv1.SigmaConfigProvider) { s.Tag = "release-2026-09" })
	got, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "feature_flags"})
	if err != nil || string(got) != "old" {
		t.Fatalf("store tag: got %q, %v", got, err)
	}

	f2 := newFakeAPI(t, defaultParams()...)
	c2 := newTestClient(t, f2, newTestCaches(), nil)
	got, err = get(t, c2, esv1.ExternalSecretDataRemoteRef{Key: "feature_flags", Version: "release-2026-09"})
	if err != nil || string(got) != "old" {
		t.Fatalf("remoteRef.version: got %q, %v", got, err)
	}
	for _, r := range f2.requests() {
		if strings.HasSuffix(r.path, "/parameters/") && r.query.Get("tag") != "release-2026-09" {
			t.Errorf("tag not sent: %v", r.query)
		}
	}
}

func TestPagination(t *testing.T) { // U-09
	f := newFakeAPI(t, defaultParams()...)
	f.pageSize = 2
	c := newTestClient(t, f, newTestCaches(), nil)
	got, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "aws_pulled"}) // last item, on page 4
	if err == nil {
		t.Fatalf("expected the external error for the last item, got %q", got)
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("last page not read: %v", err)
	}
	if n := f.count("/api/v1/projects/" + testProjectID + "/parameters/"); n != 4 {
		t.Fatalf("expected 4 page requests, got %d", n)
	}
}

func TestPaginationRefusesForeignNext(t *testing.T) {
	f := newFakeAPI(t, defaultParams()...)
	f.override = func(w http.ResponseWriter, r *http.Request, _ int) bool {
		if strings.HasSuffix(r.URL.Path, "/parameters/") {
			writeJSON(w, http.StatusOK, map[string]any{"count": 2, "next": "https://elsewhere.example/api/v1/x/", "results": []any{}})
			return true
		}
		return false
	}
	c := newTestClient(t, f, newTestCaches(), nil)
	if _, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err == nil {
		t.Fatal("expected an error for a next link on another host")
	}
}

func TestNonHTTPSRefused(t *testing.T) { // U-10
	_, err := newClient(testSpec(func(s *esv1.SigmaConfigProvider) { s.Server = "http://api.cloudtruth.io" }), testAPIKey, nil, nil)
	if !errors.Is(err, errInsecureServer) {
		t.Fatalf("expected errInsecureServer, got %v", err)
	}
}

func TestMetricsPerCall(t *testing.T) { // U-11, U-81
	f := newFakeAPI(t, defaultParams()...)
	c := newTestClient(t, f, newTestCaches(), func(s *esv1.SigmaConfigProvider) { s.Tag = "release-2026-09" })
	before := apiCallCounts(t)
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "feature_flags"}); err != nil {
		t.Fatal(err)
	}
	after := apiCallCounts(t)
	for _, call := range []string{CallProjectLookup, CallEnvironmentLookup, CallTagLookup, CallParameterList} {
		if after[call] <= before[call] {
			t.Errorf("no metric recorded for %s", call)
		}
	}
}

// apiCallCounts sums the provider API call counter per call label and checks the label set.
func apiCallCounts(t *testing.T) map[string]float64 {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range families {
		if mf.GetName() != "externalsecret_provider_api_calls_count" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := labelMap(m)
			if labels["provider"] != ProviderSigmaConfig {
				continue
			}
			if len(labels) != 3 {
				t.Errorf("unexpected label set %v", labels)
			}
			for _, v := range labels {
				if strings.Contains(v, testProject) || strings.Contains(v, testAPIKey) || strings.Contains(v, dbPassword) {
					t.Errorf("metric label leaks data: %v", labels)
				}
			}
			out[labels["call"]] += m.GetCounter().GetValue()
		}
	}
	return out
}

func labelMap(m *dto.Metric) map[string]string {
	out := map[string]string{}
	for _, l := range m.GetLabel() {
		out[l.GetName()] = l.GetValue()
	}
	return out
}

// --- 2.2 Read behavior ---

func TestGetSecret(t *testing.T) {
	f := newFakeAPI(t, defaultParams()...)
	c := newTestClient(t, f, newTestCaches(), nil)
	tests := []struct {
		name     string
		ref      esv1.ExternalSecretDataRemoteRef
		want     string
		wantNone bool
		wantErr  string
	}{
		{name: "U-20 exact name", ref: esv1.ExternalSecretDataRemoteRef{Key: "db_password"}, want: dbPassword},
		{name: "U-20 case sensitive", ref: esv1.ExternalSecretDataRemoteRef{Key: "DB_PASSWORD"}, wantNone: true},
		{name: "U-22 property string", ref: esv1.ExternalSecretDataRemoteRef{Key: "stripe", Property: "secret_key"}, want: "fictional-sk"},
		{name: "U-22 property object", ref: esv1.ExternalSecretDataRemoteRef{Key: "stripe", Property: "limits"}, want: `{"daily":5}`},
		{name: "U-22 property missing", ref: esv1.ExternalSecretDataRemoteRef{Key: "stripe", Property: "nope"}, wantErr: `property "nope" not found in parameter "stripe"`},
		{name: "U-23 absent name", ref: esv1.ExternalSecretDataRemoteRef{Key: "no_such_param"}, wantNone: true},
		{name: "U-24 null value", ref: esv1.ExternalSecretDataRemoteRef{Key: "dev_only"}, wantNone: true},
		{name: "U-21 no entry for environment", ref: esv1.ExternalSecretDataRemoteRef{Key: "not_in_env"}, wantNone: true},
		{name: "U-25 integer stays a string", ref: esv1.ExternalSecretDataRemoteRef{Key: "max_connections"}, want: "25"},
		{name: "U-62 external error", ref: esv1.ExternalSecretDataRemoteRef{Key: "aws_pulled"}, wantErr: "AccessDenied"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := get(t, c, tc.ref)
			switch {
			case tc.wantNone:
				if !errors.Is(err, esv1.NoSecretErr) {
					t.Fatalf("expected NoSecretErr, got %q, %v", got, err)
				}
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
			default:
				if err != nil || string(got) != tc.want {
					t.Fatalf("got %q, %v; want %q", got, err, tc.want)
				}
			}
		})
	}
}

func TestReadOnlyAndUnsupported(t *testing.T) { // U-30, U-31
	c := newTestClient(t, newFakeAPI(t), newTestCaches(), nil)
	ctx := context.Background()
	if err := c.PushSecret(ctx, nil, nil); !errors.Is(err, errReadOnly) {
		t.Errorf("PushSecret: %v", err)
	}
	if err := c.DeleteSecret(ctx, nil); !errors.Is(err, errReadOnly) {
		t.Errorf("DeleteSecret: %v", err)
	}
	if ok, err := c.SecretExists(ctx, nil); ok || !errors.Is(err, errReadOnly) {
		t.Errorf("SecretExists: %v, %v", ok, err)
	}
	if NewProvider().Capabilities() != esv1.SecretStoreReadOnly {
		t.Error("capabilities are not read-only")
	}
	if err := c.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// --- 2.3 Validation ---

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*esv1.SigmaConfigProvider)
		setup   func(*fakeAPI)
		wantErr string
	}{
		{name: "U-44 all exist", mutate: func(s *esv1.SigmaConfigProvider) { s.Tag = "release-2026-09" }},
		{name: "U-45 bad key", setup: func(f *fakeAPI) {
			f.override = func(w http.ResponseWriter, _ *http.Request, _ int) bool {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Invalid Api-Key."})
				return true
			}
		}, wantErr: `authentication failed (HTTP 401): check the API key in Secret "sigma-config-api-key", key "api-key"`},
		{name: "U-45 project", mutate: func(s *esv1.SigmaConfigProvider) { s.Project = "restricted-ledger" }, wantErr: `project "restricted-ledger": project not found or not visible to this API key`},
		{name: "U-45 environment", mutate: func(s *esv1.SigmaConfigProvider) { s.Environment = "staging" }, wantErr: `environment "staging" not found`},
		{name: "U-45 tag", mutate: func(s *esv1.SigmaConfigProvider) { s.Tag = "no-such-tag" }, wantErr: `tag "no-such-tag" not found in environment "production"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, defaultParams()...)
			if tc.setup != nil {
				tc.setup(f)
			}
			c := newTestClient(t, f, newTestCaches(), tc.mutate)
			res, err := c.Validate()
			if tc.wantErr == "" {
				if err != nil || res != esv1.ValidationResultReady {
					t.Fatalf("got %v, %v", res, err)
				}
				return
			}
			if res != esv1.ValidationResultError || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, %v; want error containing %q", res, err, tc.wantErr)
			}
			assertNoLeak(t, err)
		})
	}
}

func TestDefaults(t *testing.T) { // U-46
	c, err := newClient(testSpec(func(s *esv1.SigmaConfigProvider) { s.Environment = "" }), testAPIKey, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.server != "https://api.cloudtruth.io" || c.environment != "default" {
		t.Fatalf("defaults: server %q, environment %q", c.server, c.environment)
	}
}

// --- 2.4 Error mapping ---

func TestErrorMapping(t *testing.T) {
	type resp struct {
		status     int
		json       any
		html       bool
		retryAfter string
	}
	tests := []struct {
		name     string
		respond  []resp // answers to successive parameter-list requests; the last repeats
		wantErr  string
		wantReqs int // parameter-list requests expected, 0 = don't check
	}{
		{name: "U-53 as_of and tag", respond: []resp{{status: 400, json: map[string]string{"detail": "Cannot specify `as_of` and `tag` together."}}}, wantErr: "provider bug"},
		{name: "U-54 401", respond: []resp{{status: 401, json: map[string]string{"detail": "Invalid Api-Key."}}}, wantErr: `key "api-key"`},
		{name: "U-55 403 JSON", respond: []resp{{status: 403, json: map[string]string{"detail": "You do not have permission to perform this action."}}}, wantErr: "role and grants", wantReqs: 1},
		{name: "U-56 403 HTML", respond: []resp{{status: 403, html: true}}, wantErr: "blocked before reaching Sigma Config", wantReqs: 1},
		{name: "U-57 environment", respond: []resp{{status: 404, json: map[string]string{"detail": "Environment(s) not found: production"}}}, wantErr: `environment "production" not found`},
		{name: "U-63 429", respond: []resp{{status: 429, json: map[string]string{"detail": "Request was throttled."}, retryAfter: "120"}}, wantErr: "Retry-After: 120", wantReqs: 1},
		{name: "U-64 502 then 200", respond: []resp{{status: 502, html: true}, {status: 200}}, wantReqs: 2},
		{name: "U-65 503 twice", respond: []resp{{status: 503, html: true}}, wantErr: "HTTP 503 Service Unavailable", wantReqs: 2},
		{name: "U-67 other 4xx", respond: []resp{{status: 409, json: map[string]string{"detail": "Conflict."}}}, wantErr: "HTTP 409", wantReqs: 1},
		{name: "U-68 non-JSON body", respond: []resp{{status: 500, html: true}}, wantErr: "HTTP 500 Internal Server Error", wantReqs: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, defaultParams()...)
			var mu sync.Mutex
			i := 0
			f.override = func(w http.ResponseWriter, r *http.Request, _ int) bool {
				if !strings.HasSuffix(r.URL.Path, "/parameters/") {
					return false
				}
				mu.Lock()
				rsp := tc.respond[min(i, len(tc.respond)-1)]
				i++
				mu.Unlock()
				if rsp.status == 200 {
					return false
				}
				if rsp.retryAfter != "" {
					w.Header().Set("Retry-After", rsp.retryAfter)
				}
				if rsp.html {
					writeHTML(w, rsp.status)
				} else {
					writeJSON(w, rsp.status, rsp.json)
				}
				return true
			}
			c := newTestClient(t, f, newTestCaches(), nil)
			got, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
			if tc.wantErr == "" {
				if err != nil || string(got) != dbPassword {
					t.Fatalf("got %q, %v", got, err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				assertNoLeak(t, err)
			}
			if tc.wantReqs > 0 {
				if n := f.count("/api/v1/projects/" + testProjectID + "/parameters/"); n != tc.wantReqs {
					t.Fatalf("expected %d parameter requests, got %d", tc.wantReqs, n)
				}
			}
		})
	}
}

func TestProjectNotVisible(t *testing.T) { // U-50
	c := newTestClient(t, newFakeAPI(t, defaultParams()...), newTestCaches(), func(s *esv1.SigmaConfigProvider) { s.Project = "restricted-ledger" })
	_, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if err == nil || !strings.Contains(err.Error(), "not visible to this API key") || !strings.Contains(err.Error(), "grants") {
		t.Fatalf("got %v", err)
	}
}

func TestTagNotFound(t *testing.T) { // U-58
	f := newFakeAPI(t, defaultParams()...)
	c := newTestClient(t, f, newTestCaches(), nil)
	_, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "feature_flags", Version: "v1"})
	if err == nil || !strings.Contains(err.Error(), `tag "v1" not found in environment "production"`) {
		t.Fatalf("got %v", err)
	}
}

func TestStaleProjectIDIsResolvedAgain(t *testing.T) { // U-59
	f := newFakeAPI(t, defaultParams()...)
	caches := newTestCaches()
	c := newTestClient(t, f, caches, nil)
	if _, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err != nil {
		t.Fatal(err)
	}
	// The project was deleted and re-created: same name, new ID.
	f.mu.Lock()
	f.projects[testProject] = "44444444-4444-4444-4444-444444444444"
	f.mu.Unlock()
	caches.clock.Advance(cacheTTL)
	got, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if err != nil || string(got) != dbPassword {
		t.Fatalf("got %q, %v", got, err)
	}
	if n := f.count("/api/v1/projects/"); n < 2 || f.requests()[len(f.requests())-1].path != "/api/v1/projects/44444444-4444-4444-4444-444444444444/parameters/" {
		t.Fatalf("project was not re-resolved: %+v", f.requests())
	}
}

func TestTemplateErrorFallback(t *testing.T) { // U-60, U-61, U-78
	params := append(defaultParams(), fakeParam{name: "pool_size", template: true})
	f := newFakeAPI(t, params...)
	caches := newTestCaches()
	c := newTestClient(t, f, caches, nil)
	bulkPath := "/api/v1/projects/" + testProjectID + "/parameters/"

	// A healthy key is still readable through the by-name fallback (P-17).
	got, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if err != nil || string(got) != dbPassword {
		t.Fatalf("healthy key: got %q, %v", got, err)
	}
	// The broken key is named, without the API's message (it can quote rendered values).
	_, err = get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "pool_size"})
	if err == nil || !strings.Contains(err.Error(), `parameter "pool_size"`) || strings.Contains(err.Error(), "missing_ref") {
		t.Fatalf("broken key: %v", err)
	}
	assertNoLeak(t, err)

	// U-78: within 30 s the failed bulk and both by-name results come from the cache.
	n := f.count(bulkPath)
	for range 3 {
		_, _ = get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
		_, _ = get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "pool_size"})
	}
	if f.count(bulkPath) != n {
		t.Fatalf("expected no new requests within the TTL, went from %d to %d", n, f.count(bulkPath))
	}
	if n != 3 { // 1 failed bulk + 2 by-name
		t.Fatalf("expected 3 parameter requests, got %d", n)
	}
	caches.clock.Advance(cacheTTL)
	_, _ = get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if f.count(bulkPath) != n+2 { // bulk again + by-name again
		t.Fatalf("expected a refetch after the TTL, got %d requests", f.count(bulkPath))
	}
}

func TestTimeoutRetriesOnce(t *testing.T) { // U-66
	f := newFakeAPI(t, defaultParams()...)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.override = func(_ http.ResponseWriter, r *http.Request, _ int) bool {
		if strings.HasSuffix(r.URL.Path, "/parameters/") {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return true
		}
		return false
	}
	c := newTestClient(t, f, newTestCaches(), nil)
	httpClient := f.srv.Client()
	httpClient.Timeout = 50 * time.Millisecond
	c2, err := newClient(testSpec(func(s *esv1.SigmaConfigProvider) { s.Server = f.srv.URL }), testAPIKey, httpClient, func(context.Context, time.Duration) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c2.snapshots, c2.projectIDs = c.snapshots, c.projectIDs
	if _, err := get(t, c2, esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err == nil {
		t.Fatal("expected a timeout error")
	}
	if n := f.count("/api/v1/projects/" + testProjectID + "/parameters/"); n != 2 {
		t.Fatalf("expected exactly one retry (2 requests), got %d", n)
	}
}

// --- 2.5 Cache ---

func TestCacheSharesOneBulkRequest(t *testing.T) { // U-70, U-72, U-73, U-76
	f := newFakeAPI(t, defaultParams()...)
	caches := newTestCaches()
	bulkPath := "/api/v1/projects/" + testProjectID + "/parameters/"
	for _, key := range []string{"db_password", "stripe", "max_connections"} {
		c := newTestClient(t, f, caches, nil) // a new client per reconcile, as ESO does
		if _, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: key}); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count(bulkPath); n != 1 {
		t.Fatalf("expected 1 bulk request for 3 keys, got %d", n)
	}
	caches.clock.Advance(cacheTTL - time.Second)
	_, _ = get(t, newTestClient(t, f, caches, nil), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if n := f.count(bulkPath); n != 1 {
		t.Fatalf("expected the entry to live for 30 s, got %d bulk requests", n)
	}
	caches.clock.Advance(time.Second)
	_, _ = get(t, newTestClient(t, f, caches, nil), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if n := f.count(bulkPath); n != 2 {
		t.Fatalf("expected a refetch at 30 s, got %d bulk requests", n)
	}
	if n := f.count("/api/v1/projects/") - f.count(bulkPath); n != 1 {
		t.Fatalf("expected the project to be resolved once, got %d lookups", n)
	}
}

func TestCacheKeysAreSeparate(t *testing.T) { // U-74
	f := newFakeAPI(t, defaultParams()...)
	caches := newTestCaches()
	bulkPath := "/api/v1/projects/" + testProjectID + "/parameters/"
	variants := []func(*esv1.SigmaConfigProvider){
		nil,
		func(s *esv1.SigmaConfigProvider) { s.Tag = "release-2026-09" },
		func(s *esv1.SigmaConfigProvider) { s.Environment = "default" },
	}
	for _, v := range variants {
		_, _ = get(t, newTestClient(t, f, caches, v), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	}
	other, err := newClient(testSpec(func(s *esv1.SigmaConfigProvider) { s.Server = f.srv.URL }), "fakeprefix.another-key", f.srv.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	other.snapshots, other.projectIDs = caches.snapshots, caches.projectIDs
	_, _ = get(t, other, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if n := f.count(bulkPath); n != 4 {
		t.Fatalf("expected 4 separate bulk requests, got %d", n)
	}
}

func TestCacheKeyHoldsNoAPIKey(t *testing.T) { // U-75
	f := newFakeAPI(t, defaultParams()...)
	caches := newTestCaches()
	c := newTestClient(t, f, caches, nil)
	_, _ = get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if c.keyHash == testAPIKey || strings.Contains(c.keyHash, testAPIKey) {
		t.Fatal("keyHash holds the key")
	}
	caches.snapshots.mu.Lock()
	defer caches.snapshots.mu.Unlock()
	for k := range caches.snapshots.entries {
		if strings.Contains(k, testAPIKey) || strings.Contains(k, testProject) {
			t.Fatalf("cache key not hashed: %q", k)
		}
	}
}

func TestConcurrentMissesShareOneFetch(t *testing.T) { // U-77
	f := newFakeAPI(t, defaultParams()...)
	caches := newTestCaches()
	gate := make(chan struct{})
	f.override = func(_ http.ResponseWriter, r *http.Request, _ int) bool {
		if strings.HasSuffix(r.URL.Path, "/parameters/") {
			<-gate
		}
		return false
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := get(t, newTestClient(t, f, caches, nil), esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(100 * time.Millisecond) // let the goroutines pile up on the miss
	close(gate)
	wg.Wait()
	if n := f.count("/api/v1/projects/" + testProjectID + "/parameters/"); n != 1 {
		t.Fatalf("expected 1 bulk request for 20 concurrent misses, got %d", n)
	}
}

func TestCancelledFetchIsNotCached(t *testing.T) {
	f := newFakeAPI(t, defaultParams()...)
	caches := newTestCaches()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newTestClient(t, f, caches, nil).GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err == nil {
		t.Fatal("expected an error with a canceled context")
	}
	got, err := get(t, newTestClient(t, f, caches, nil), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if err != nil || string(got) != dbPassword {
		t.Fatalf("a canceled fetch was cached: %q, %v", got, err)
	}
}

// --- 2.6 Secrets never leak ---

// assertNoLeak checks an error message for the API key and every fixture value (U-80).
func assertNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, secret := range []string{testAPIKey, dbPassword, "fictional-sk", "fictional-pk", "stale"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error leaks %q: %s", secret, msg)
		}
	}
}
