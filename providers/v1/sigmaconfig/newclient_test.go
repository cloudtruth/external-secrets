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
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// storeFor builds a SecretStore in namespace "default" pointing at the fake server.
func storeFor(f *fakeAPI, mutate func(*esv1.SigmaConfigProvider)) *esv1.SecretStore {
	spec := testSpec(func(s *esv1.SigmaConfigProvider) {
		s.Server = f.srv.URL
		if mutate != nil {
			mutate(s)
		}
	})
	return &esv1.SecretStore{
		Kind:      esv1.SecretStoreKind,
		Name:      "store",
		Namespace: "default",
		Spec:      esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{SigmaConfig: spec}},
	}
}

func serverCAPEM(f *fakeAPI) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func kubeWith(objs ...*corev1.Secret) *clientfake.ClientBuilder {
	b := clientfake.NewClientBuilder()
	for _, o := range objs {
		b = b.WithObjects(o)
	}
	return b
}

func apiKeySecret() *corev1.Secret {
	return &corev1.Secret{
		Name: "sigma-config-api-key", Namespace: "default",
		Data: map[string][]byte{"api-key": []byte(testAPIKey)},
	}
}

// resetSharedCaches gives each NewClient test fresh process-wide caches.
func resetSharedCaches(t *testing.T) {
	t.Helper()
	oldSnap, oldIDs := sharedSnapshots, sharedProjectIDs
	caches := newTestCaches()
	sharedSnapshots, sharedProjectIDs = caches.snapshots, caches.projectIDs
	t.Cleanup(func() { sharedSnapshots, sharedProjectIDs = oldSnap, oldIDs })
}

func TestNewClientReadsKeyAndTrustsCABundle(t *testing.T) { // U-01, U-83
	resetSharedCaches(t)
	f := newFakeAPI(t, defaultParams()...)
	kube := kubeWith(apiKeySecret()).Build()
	store := storeFor(f, func(s *esv1.SigmaConfigProvider) { s.CABundle = serverCAPEM(f) })

	sc, err := NewProvider().NewClient(context.Background(), store, kube, "default")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := sc.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if err != nil || string(got) != dbPassword {
		t.Fatalf("got %q, %v", got, err)
	}
	if h := f.requests()[0].header.Get("Authorization"); h != "Api-Key "+testAPIKey {
		t.Fatalf("Authorization = %q", h)
	}
}

// U-85: the fake server offers HTTP/2. The client must negotiate HTTP/1.1, because its
// transport cannot read HTTP/2 frames (staging answered P-01 with an HTTP/2 SETTINGS frame).
func TestNewClientNegotiatesHTTP1WithHTTP2Server(t *testing.T) {
	resetSharedCaches(t)
	f := newFakeAPI(t, defaultParams()...)
	store := storeFor(f, func(s *esv1.SigmaConfigProvider) { s.CABundle = serverCAPEM(f) })

	sc, err := NewProvider().NewClient(context.Background(), store, kubeWith(apiKeySecret()).Build(), "default")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := sc.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err != nil {
		t.Fatalf("GetSecret against an HTTP/2-capable server: %v", err)
	}
	for _, r := range f.requests() {
		if r.proto != "HTTP/1.1" {
			t.Fatalf("request %s used %s, want HTTP/1.1", r.path, r.proto)
		}
	}
}

// U-85: with or without a CA, the client offers only http/1.1 in ALPN. Without a CA the
// fake server's certificate is untrusted, so this checks the transport's TLS settings.
func TestHTTPClientOffersOnlyHTTP1(t *testing.T) {
	f := newFakeAPI(t)
	for name, mutate := range map[string]func(*esv1.SigmaConfigProvider){
		"no CA":     nil,
		"CA bundle": func(s *esv1.SigmaConfigProvider) { s.CABundle = serverCAPEM(f) },
	} {
		t.Run(name, func(t *testing.T) {
			spec := storeFor(f, mutate).Spec.Provider.SigmaConfig
			hc, err := newHTTPClient(context.Background(), spec, esv1.SecretStoreKind, "default", kubeWith().Build())
			if err != nil {
				t.Fatalf("newHTTPClient: %v", err)
			}
			tr, ok := hc.Transport.(*http.Transport)
			if !ok || tr.TLSClientConfig == nil {
				t.Fatal("transport has no TLS config")
			}
			if got := tr.TLSClientConfig.NextProtos; !reflect.DeepEqual(got, []string{"http/1.1"}) {
				t.Fatalf("ALPN offers %v, want [http/1.1]", got)
			}
			if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
				t.Fatalf("MinVersion = %x, want TLS 1.2", tr.TLSClientConfig.MinVersion)
			}
		})
	}
}

func TestNewClientRejectsUntrustedServer(t *testing.T) { // U-83
	resetSharedCaches(t)
	f := newFakeAPI(t, defaultParams()...)
	sc, err := NewProvider().NewClient(context.Background(), storeFor(f, nil), kubeWith(apiKeySecret()).Build(), "default")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = sc.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected a TLS verification error without the CA, got %v", err)
	}
	if len(f.requests()) != 0 {
		t.Fatal("a request reached the untrusted server")
	}
}

func TestNewClientCAProvider(t *testing.T) { // U-84
	resetSharedCaches(t)
	f := newFakeAPI(t, defaultParams()...)
	caSecret := &corev1.Secret{
		Name: "corp-ca", Namespace: "default",
		Data: map[string][]byte{"ca.crt": serverCAPEM(f)},
	}
	withCA := func(name string) *esv1.SecretStore {
		return storeFor(f, func(s *esv1.SigmaConfigProvider) {
			s.CAProvider = &esv1.CAProvider{Type: esv1.CAProviderTypeSecret, Name: name, Key: "ca.crt"}
		})
	}

	sc, err := NewProvider().NewClient(context.Background(), withCA("corp-ca"), kubeWith(apiKeySecret(), caSecret).Build(), "default")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got, err := sc.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: "db_password"}); err != nil || string(got) != dbPassword {
		t.Fatalf("got %q, %v", got, err)
	}

	_, err = NewProvider().NewClient(context.Background(), withCA("missing-ca"), kubeWith(apiKeySecret()).Build(), "default")
	if err == nil || !strings.Contains(err.Error(), "missing-ca") {
		t.Fatalf("expected an error naming the CA reference, got %v", err)
	}
}

func TestNewClientMissingKeySecret(t *testing.T) {
	resetSharedCaches(t)
	f := newFakeAPI(t)
	_, err := NewProvider().NewClient(context.Background(), storeFor(f, nil), kubeWith().Build(), "default")
	if err == nil || !strings.Contains(err.Error(), `Secret "sigma-config-api-key", key "api-key"`) {
		t.Fatalf("got %v", err)
	}
}

func TestNoInsecureOption(t *testing.T) { // U-82
	typ := reflect.TypeFor[esv1.SigmaConfigProvider]()
	for field := range typ.Fields() {
		name := strings.ToLower(field.Name)
		if strings.Contains(name, "insecure") || strings.Contains(name, "skip") || strings.Contains(name, "verify") {
			t.Errorf("field %s looks like a TLS bypass", field.Name)
		}
	}
}
