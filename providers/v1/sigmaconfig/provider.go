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

// Package sigmaconfig implements a read-only Provider for [Sigma Config]
// (formerly CloudTruth).
//
// [Sigma Config]: https://cloudtruth.com/
package sigmaconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/sigmaconfig/api"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
	"github.com/external-secrets/external-secrets/runtime/metrics"
)

var _ esv1.Provider = &Provider{}

var (
	errMissingProvider = errors.New("missing sigmaconfig provider spec")
	errMissingProject  = errors.New("sigmaconfig: project is required")
	errInsecureServer  = errors.New("sigmaconfig: server must be an https:// URL")
	// errMissingAPIKeyRef: the CRD requires the field, but name and key can still be empty strings.
	errMissingAPIKeyRef = errors.New("sigmaconfig: auth.apiKeySecretRef needs both name and key")
)

// Provider is the Sigma Config provider.
type Provider struct{}

// NewProvider creates a new Provider instance.
func NewProvider() esv1.Provider {
	return &Provider{}
}

// ProviderSpec returns the provider specification for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		SigmaConfig: &esv1.SigmaConfigProvider{},
	}
}

// MaintenanceStatus returns the maintenance status of the provider.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}

// Capabilities returns SecretStoreReadOnly: the provider never writes to Sigma Config.
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

// NewClient builds a SecretsClient for the store. It reads the API key from the referenced
// Secret and, when caBundle or caProvider is set, adds that CA to the system roots.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube client.Client, namespace string) (esv1.SecretsClient, error) {
	spec, err := getProvider(store)
	if err != nil {
		return nil, err
	}
	apiKey, err := resolvers.SecretKeyRef(ctx, kube, store.GetKind(), namespace, &spec.Auth.APIKeySecretRef)
	if err != nil {
		return nil, fmt.Errorf("sigmaconfig: reading the API key from Secret %q, key %q: %w", spec.Auth.APIKeySecretRef.Name, spec.Auth.APIKeySecretRef.Key, err)
	}
	httpClient, err := newHTTPClient(ctx, spec, store.GetKind(), namespace, kube)
	if err != nil {
		return nil, err
	}
	return newClient(spec, apiKey, httpClient, nil)
}

// newClient wires a client to the process-wide caches. sleep is only set by tests.
func newClient(spec *esv1.SigmaConfigProvider, apiKey string, httpClient *http.Client, sleep func(context.Context, time.Duration) error) (*secretsClient, error) {
	server := spec.Server
	if server == "" {
		server = defaultServer
	}
	environment := spec.Environment
	if environment == "" {
		environment = defaultEnvironment
	}
	ac, err := api.New(api.Options{
		Server:     server,
		APIKey:     apiKey,
		UserAgent:  userAgent(),
		HTTPClient: httpClient,
		Observe:    func(call string, err error) { metrics.ObserveAPICall(ProviderSigmaConfig, call, err) },
		Sleep:      sleep,
	})
	if err != nil {
		return nil, errInsecureServer
	}
	return &secretsClient{
		api:         ac,
		server:      server,
		keyHash:     hashKey(apiKey),
		keyRef:      spec.Auth.APIKeySecretRef,
		project:     spec.Project,
		environment: environment,
		tag:         spec.Tag,
		snapshots:   sharedSnapshots,
		projectIDs:  sharedProjectIDs,
	}, nil
}

// newHTTPClient returns a client with a 30 s timeout. TLS verification is always on; a
// configured CA is added to the system roots, never used to replace them.
func newHTTPClient(ctx context.Context, spec *esv1.SigmaConfigProvider, storeKind, namespace string, kube client.Client) (*http.Client, error) {
	transport, err := esutils.CloneDefaultHTTPTransport()
	if err != nil {
		return nil, fmt.Errorf("sigmaconfig: %w", err)
	}
	ca, err := esutils.FetchCACertFromSource(ctx, esutils.CreateCertOpts{
		CABundle:   spec.CABundle,
		CAProvider: spec.CAProvider,
		StoreKind:  storeKind,
		Namespace:  namespace,
		Client:     kube,
	})
	if err != nil {
		return nil, fmt.Errorf("sigmaconfig: loading the CA certificate: %w", err)
	}
	if len(ca) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("sigmaconfig: the CA certificate is not valid PEM")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: requestTimeout}, nil
}

// userAgent is "external-secrets/<version> sigmaconfig-provider" (FR-14).
func userAgent() string {
	version := "dev"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
	return "external-secrets/" + version + " sigmaconfig-provider"
}

// ValidateStore checks the store spec without calling the Sigma Config API.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	spec, err := getProvider(store)
	if err != nil {
		return nil, err
	}
	if spec.Project == "" {
		return nil, errMissingProject
	}
	if spec.Server != "" {
		u, err := url.Parse(spec.Server)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errInsecureServer
		}
	}
	if spec.Auth.APIKeySecretRef.Name == "" || spec.Auth.APIKeySecretRef.Key == "" {
		return nil, errMissingAPIKeyRef
	}
	if err := esutils.ValidateSecretSelector(store, spec.Auth.APIKeySecretRef); err != nil {
		return nil, fmt.Errorf("sigmaconfig: invalid auth.apiKeySecretRef: %w", err)
	}
	return nil, nil
}

func getProvider(store esv1.GenericStore) (*esv1.SigmaConfigProvider, error) {
	if store == nil {
		return nil, errMissingProvider
	}
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.SigmaConfig == nil {
		return nil, errMissingProvider
	}
	return spec.Provider.SigmaConfig, nil
}
