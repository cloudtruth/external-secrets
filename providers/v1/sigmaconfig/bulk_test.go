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
	"maps"
	"slices"
	"strings"
	"testing"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestGetSecretMap(t *testing.T) { // U-26, U-27
	params := append(defaultParams(),
		fakeParam{name: "json_list", value: new(`["a","b"]`)},
		fakeParam{name: "broken_json", value: new(`{"a":`)},
	)
	c := newTestClient(t, newFakeAPI(t, params...), newTestCaches(), nil)
	ctx := context.Background()

	got, err := c.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{Key: "stripe"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"secret_key": "fictional-sk", "publishable_key": "fictional-pk", "limits": `{"daily":5}`}
	if len(got) != len(want) {
		t.Fatalf("got keys %v", slices.Sorted(maps.Keys(got)))
	}
	for k, v := range want {
		if string(got[k]) != v {
			t.Errorf("key %s: got %q, want %q", k, got[k], v)
		}
	}

	// property narrows to a nested object first.
	got, err = c.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{Key: "stripe", Property: "limits"})
	if err != nil || string(got["daily"]) != "5" || len(got) != 1 {
		t.Fatalf("property: got %v, %v", got, err)
	}

	for _, key := range []string{"db_password", "json_list", "max_connections", "broken_json"} {
		_, err := c.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{Key: key})
		if err == nil || !strings.Contains(err.Error(), `parameter "`+key+`"`) {
			t.Errorf("%s: expected an error naming the parameter, got %v", key, err)
		}
		assertNoLeak(t, err)
	}

	if _, err := c.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{Key: "dev_only"}); !errors.Is(err, esv1.NoSecretErr) {
		t.Errorf("null value: expected NoSecretErr, got %v", err)
	}
}

func TestGetAllSecrets(t *testing.T) { // U-28, U-29
	params := append(defaultParams(),
		fakeParam{name: "db_url", value: new("postgres://fictional-host/db")},
		fakeParam{name: "db host/primary", value: new("fictional-host")},
		fakeParam{name: "db_unset", value: nil},
	)
	c := newTestClient(t, newFakeAPI(t, params...), newTestCaches(), nil)

	got, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^db"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"db host/primary", "db_password", "db_url"} // db_unset skipped, names unchanged
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, want) {
		t.Fatalf("got keys %v, want %v", keys, want)
	}
	if string(got["db_password"]) != dbPassword {
		t.Error("db_password value mismatch")
	}
}

func TestGetAllSecretsUnsupported(t *testing.T) { // U-30
	c := newTestClient(t, newFakeAPI(t, defaultParams()...), newTestCaches(), nil)
	ctx := context.Background()
	path := "secrets/"
	tests := []struct {
		name string
		find esv1.ExternalSecretFind
		want error
	}{
		{name: "tags", find: esv1.ExternalSecretFind{Tags: map[string]string{"team": "a"}}, want: errFindTags},
		{name: "path", find: esv1.ExternalSecretFind{Path: &path, Name: &esv1.FindName{RegExp: ".*"}}, want: errFindPath},
		{name: "no name", find: esv1.ExternalSecretFind{}, want: errFindName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.GetAllSecrets(ctx, tc.find); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := c.GetAllSecrets(ctx, esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "("}}); err == nil {
		t.Fatal("expected an error for an invalid regexp")
	}
}

func TestGetAllSecretsTemplateError(t *testing.T) { // U-60 (bulk half), P-18
	params := append(defaultParams(), fakeParam{name: "pool_size", template: true})
	c := newTestClient(t, newFakeAPI(t, params...), newTestCaches(), nil)
	_, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: ".*"}})
	if err == nil || !strings.Contains(err.Error(), "fails to evaluate") || strings.Contains(err.Error(), "missing_ref") {
		t.Fatalf("got %v", err)
	}
	assertNoLeak(t, err)
}

func TestGetAllSecretsExternalError(t *testing.T) {
	c := newTestClient(t, newFakeAPI(t, defaultParams()...), newTestCaches(), nil)
	_, err := c.GetAllSecrets(context.Background(), esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^aws_"}})
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("got %v", err)
	}
	assertNoLeak(t, err)
}

func TestAllReadsShareOneEntry(t *testing.T) { // U-71
	f := newFakeAPI(t, defaultParams()...)
	caches := newTestCaches()
	ctx := context.Background()
	c := newTestClient(t, f, caches, nil)
	if _, err := c.GetSecret(ctx, esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSecretMap(ctx, esv1.ExternalSecretDataRemoteRef{Key: "stripe"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAllSecrets(ctx, esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^max_"}}); err != nil {
		t.Fatal(err)
	}
	if n := f.count("/api/v1/projects/" + testProjectID + "/parameters/"); n != 1 {
		t.Fatalf("expected 1 bulk request for all three read paths, got %d", n)
	}
}
