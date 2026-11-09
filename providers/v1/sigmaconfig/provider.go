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
	"errors"
	"fmt"
	"net/url"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
)

var _ esv1.Provider = &Provider{}

var (
	errMissingProvider = errors.New("missing sigmaconfig provider spec")
	errMissingProject  = errors.New("sigmaconfig: project is required")
	errInsecureServer  = errors.New("sigmaconfig: server must be an https:// URL")
	errNotImplemented  = errors.New("sigmaconfig: client not implemented yet")
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

// NewClient builds a SecretsClient for the store.
func (p *Provider) NewClient(_ context.Context, store esv1.GenericStore, _ client.Client, _ string) (esv1.SecretsClient, error) {
	if _, err := getProvider(store); err != nil {
		return nil, err
	}
	return nil, errNotImplemented
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
