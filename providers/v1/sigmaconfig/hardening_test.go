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
	"strconv"
	"strings"
	"testing"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/sigmaconfig/api"
)

// A failed external pull often comes with a null value. It must be an error, never "no secret",
// or deletionPolicy: Delete would remove the user's Secret on a temporary upstream failure.
func TestExternalErrorWithNullValue(t *testing.T) {
	params := append(defaultParams(), fakeParam{name: "aws_null", value: nil, extError: "AccessDenied"})
	c := newTestClient(t, newFakeAPI(t, params...), newTestCaches(), nil)

	_, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "aws_null"})
	if err == nil || errors.Is(err, esv1.NoSecretErr) || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("GetSecret: expected the external error, got %v", err)
	}

	_, err = c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^aws_null$"}})
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("GetAllSecrets: expected the external error, not a dropped key, got %v", err)
	}
}

func TestExternalErrorCodeIsSanitised(t *testing.T) {
	params := []fakeParam{{name: "aws_odd", value: nil, extError: "bad\ncode <x>"}}
	c := newTestClient(t, newFakeAPI(t, params...), newTestCaches(), nil)
	_, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "aws_odd"})
	if err == nil || strings.ContainsAny(err.Error(), "\n<>") || !strings.Contains(err.Error(), "(unrecognized)") {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	for _, target := range []string{"http-downgrade", "same-host"} {
		t.Run(target, func(t *testing.T) {
			f := newFakeAPI(t, defaultParams()...)
			f.override = func(w http.ResponseWriter, r *http.Request, _ int) bool {
				switch {
				case strings.HasSuffix(r.URL.Path, "/parameters/"):
					loc := f.srv.URL + "/moved/"
					if target == "http-downgrade" {
						loc = "http://" + strings.TrimPrefix(f.srv.URL, "https://") + "/moved/"
					}
					http.Redirect(w, r, loc, http.StatusMovedPermanently)
					return true
				case r.URL.Path == "/moved/":
					t.Errorf("redirect was followed (Authorization present: %t)", r.Header.Get("Authorization") != "")
					writeJSON(w, http.StatusOK, map[string]any{"count": 0, "results": []any{}})
					return true
				}
				return false
			}
			c := newTestClient(t, f, newTestCaches(), nil)
			_, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
			if err == nil || !strings.Contains(err.Error(), "HTTP 301") {
				t.Fatalf("expected an HTTP 301 error, got %v", err)
			}
			assertNoLeak(t, err)
			if n := f.count("/moved/"); n != 0 {
				t.Fatalf("redirect target got %d requests", n)
			}
		})
	}
}

func TestPaginationStops(t *testing.T) {
	tests := []struct {
		name     string
		next     func(f *fakeAPI, r *http.Request, n int) string
		wantReqs int
	}{
		{
			name:     "next repeats the same page",
			next:     func(f *fakeAPI, r *http.Request, _ int) string { return f.srv.URL + r.URL.RequestURI() },
			wantReqs: 1,
		},
		{
			name: "next never ends",
			next: func(f *fakeAPI, r *http.Request, n int) string {
				q := r.URL.Query()
				q.Set("page", strconv.Itoa(n+1)) // n counts requests, so every link is new
				return f.srv.URL + r.URL.Path + "?" + q.Encode()
			},
			wantReqs: api.MaxPages,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, defaultParams()...)
			f.override = func(w http.ResponseWriter, r *http.Request, n int) bool {
				if !strings.HasSuffix(r.URL.Path, "/parameters/") {
					return false
				}
				writeJSON(w, http.StatusOK, map[string]any{"count": 1, "next": tc.next(f, r, n), "results": []any{}})
				return true
			}
			c := newTestClient(t, f, newTestCaches(), nil)
			_, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
			if err == nil || !strings.Contains(err.Error(), "did not end") {
				t.Fatalf("expected a pagination error, got %v", err)
			}
			if n := f.count("/api/v1/projects/" + testProjectID + "/parameters/"); n != tc.wantReqs {
				t.Fatalf("expected %d page requests, got %d", tc.wantReqs, n)
			}
		})
	}
}

// Server text never reaches an error: it can quote a value, or carry text meant to fake log lines.
func TestServerTextIsNotCopied(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		detail     string
		retryAfter string
		want       string
	}{
		{name: "400 detail quoting a value", status: 400, detail: "value " + dbPassword + " is invalid", want: "HTTP 400"},
		{name: "404 other detail", status: 404, detail: "Thing " + dbPassword + " missing", want: "HTTP 404"},
		{name: "409 detail", status: 409, detail: dbPassword, want: "HTTP 409"},
		{name: "429 odd Retry-After", status: 429, detail: "throttled", retryAfter: "<script>", want: "Retry-After: (unrecognized)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, defaultParams()...)
			f.override = func(w http.ResponseWriter, r *http.Request, _ int) bool {
				if !strings.HasSuffix(r.URL.Path, "/parameters/") {
					return false
				}
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				writeJSON(w, tc.status, map[string]string{"detail": tc.detail})
				return true
			}
			c := newTestClient(t, f, newTestCaches(), nil)
			_, err := get(t, c, esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
			if tc.detail != "" && strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("server detail copied into the error: %v", err)
			}
			assertNoLeak(t, err)
		})
	}
}

// A panicking fill must not leave the cache locked or its waiters stuck.
func TestCacheSurvivesPanickingFill(t *testing.T) {
	cache := newSnapshotCache(time.Now)
	started := make(chan struct{})
	release := make(chan struct{})

	go func() {
		defer func() { _ = recover() }()
		cache.get(context.Background(), "k", func() *snapshot {
			close(started)
			<-release
			panic("boom")
		})
	}()
	<-started

	waiter := make(chan *snapshot, 1)
	go func() { waiter <- cache.get(context.Background(), "k", func() *snapshot { return &snapshot{} }) }()
	time.Sleep(50 * time.Millisecond) // let the waiter block on the pending fill
	close(release)

	select {
	case s := <-waiter:
		if !errors.Is(s.err, errFillPanicked) {
			t.Fatalf("waiter: expected errFillPanicked, got %v", s.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter stuck after the fill panicked")
	}

	done := make(chan *snapshot, 1)
	go func() {
		done <- cache.get(context.Background(), "k", func() *snapshot { return &snapshot{values: map[string]*paramValue{}} })
	}()
	select {
	case s := <-done:
		if s.err != nil {
			t.Fatalf("the panic was cached: %v", s.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cache deadlocked after a panicking fill")
	}
}

// A caller waiting on someone else's fill stops when its own context ends.
func TestCacheWaiterHonoursContext(t *testing.T) {
	cache := newSnapshotCache(time.Now)
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	go cache.get(context.Background(), "k", func() *snapshot {
		close(started)
		<-release
		return &snapshot{}
	})
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got := make(chan *snapshot, 1)
	go func() { got <- cache.get(ctx, "k", func() *snapshot { return &snapshot{} }) }()
	select {
	case s := <-got:
		if !errors.Is(s.err, context.DeadlineExceeded) {
			t.Fatalf("expected the waiter's own deadline, got %v", s.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter ignored its context")
	}
}
