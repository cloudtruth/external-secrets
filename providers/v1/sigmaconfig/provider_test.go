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
	"encoding/json"
	"errors"
	"testing"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

func makeStore(kind string, mutate func(*esv1.SigmaConfigProvider)) esv1.GenericStore {
	spec := esv1.SecretStoreSpec{
		Provider: &esv1.SecretStoreProvider{
			SigmaConfig: &esv1.SigmaConfigProvider{
				Project: "payments-api",
				Auth: esv1.SigmaConfigAuth{
					APIKeySecretRef: esmeta.SecretKeySelector{Name: "sigma-config-api-key", Key: "api-key"},
				},
			},
		},
	}
	if mutate != nil {
		mutate(spec.Provider.SigmaConfig)
	}
	if kind == esv1.ClusterSecretStoreKind {
		return &esv1.ClusterSecretStore{
			Kind: esv1.ClusterSecretStoreKind,
			Name: "store",
			Spec: spec,
		}
	}
	return &esv1.SecretStore{
		Kind:      esv1.SecretStoreKind,
		Name:      "store",
		Namespace: "default",
		Spec:      spec,
	}
}

func TestValidateStore(t *testing.T) {
	tests := []struct {
		name    string
		store   esv1.GenericStore
		wantErr error
		// wantAnyErr is for errors from ESO helpers, which are not exported.
		wantAnyErr bool
	}{
		{name: "valid with defaults", store: makeStore(esv1.SecretStoreKind, nil)},
		{
			name: "valid with explicit https server",
			store: makeStore(esv1.SecretStoreKind, func(p *esv1.SigmaConfigProvider) {
				p.Server = "https://api.staging.cloudtruth.io"
			}),
		},
		{
			name:    "missing provider",
			store:   &esv1.SecretStore{Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{}}},
			wantErr: errMissingProvider,
		},
		{
			name:    "missing project",
			store:   makeStore(esv1.SecretStoreKind, func(p *esv1.SigmaConfigProvider) { p.Project = "" }),
			wantErr: errMissingProject,
		},
		{
			name: "missing key selector",
			store: makeStore(esv1.SecretStoreKind, func(p *esv1.SigmaConfigProvider) {
				p.Auth.APIKeySecretRef.Name = ""
			}),
			wantErr: errMissingAPIKeyRef,
		},
		{
			name:    "http server refused",
			store:   makeStore(esv1.SecretStoreKind, func(p *esv1.SigmaConfigProvider) { p.Server = "http://api.cloudtruth.io" }),
			wantErr: errInsecureServer,
		},
		{
			name:    "server without host refused",
			store:   makeStore(esv1.SecretStoreKind, func(p *esv1.SigmaConfigProvider) { p.Server = "https://" }),
			wantErr: errInsecureServer,
		},
		{
			name: "namespaced store referencing another namespace",
			store: makeStore(esv1.SecretStoreKind, func(p *esv1.SigmaConfigProvider) {
				p.Auth.APIKeySecretRef.Namespace = new("other")
			}),
			wantAnyErr: true,
		},
		{
			name:       "cluster store without key namespace",
			store:      makeStore(esv1.ClusterSecretStoreKind, nil),
			wantAnyErr: true,
		},
		{
			name: "cluster store with key namespace",
			store: makeStore(esv1.ClusterSecretStoreKind, func(p *esv1.SigmaConfigProvider) {
				p.Auth.APIKeySecretRef.Namespace = new("eso")
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewProvider().ValidateStore(tc.store)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
			case tc.wantAnyErr:
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
			case err != nil:
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCapabilitiesReadOnly(t *testing.T) {
	if got := NewProvider().Capabilities(); got != esv1.SecretStoreReadOnly {
		t.Fatalf("expected SecretStoreReadOnly, got %v", got)
	}
}

func TestProviderSpecSetsOnlySigmaConfig(t *testing.T) {
	spec := ProviderSpec()
	if spec.SigmaConfig == nil {
		t.Fatal("ProviderSpec must set SigmaConfig")
	}
	// The registry names a provider by the single JSON key of the marshaled union.
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := keys["sigmaconfig"]; !ok || len(keys) != 1 {
		t.Fatalf("expected exactly the sigmaconfig key, got %s", raw)
	}
}
