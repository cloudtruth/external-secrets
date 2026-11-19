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

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// SigmaConfigProvider configures a store to read parameters from one Sigma Config
// (formerly CloudTruth) project in one environment, optionally pinned to a tag.
type SigmaConfigProvider struct {
	// Server is the base URL of the Sigma Config API.
	// +kubebuilder:default="https://api.cloudtruth.io"
	// +kubebuilder:validation:Pattern=`^https://`
	// +optional
	Server string `json:"server,omitempty"`

	// Project is the name of the Sigma Config project to read from. Matched exactly.
	// +kubebuilder:validation:MinLength=1
	Project string `json:"project"`

	// Environment is the name of the Sigma Config environment whose values are read.
	// +kubebuilder:default="default"
	// +optional
	Environment string `json:"environment,omitempty"`

	// Tag pins every read from this store to the values as they were at this tag
	// in the environment. remoteRef.version overrides it for a single key.
	// +optional
	Tag string `json:"tag,omitempty"`

	// Auth configures how the operator authenticates with the Sigma Config API.
	Auth SigmaConfigAuth `json:"auth"`

	// CABundle is a base64-encoded PEM CA certificate to trust in addition to the
	// system roots, for a server behind a private CA. TLS verification is always on.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`

	// CAProvider reads the CA certificate from a Secret or ConfigMap instead of CABundle.
	// +optional
	CAProvider *CAProvider `json:"caProvider,omitempty"`
}

// SigmaConfigAuth contains the credentials for the Sigma Config API.
type SigmaConfigAuth struct {
	// APIKeySecretRef references the Kubernetes Secret key that holds a Sigma Config API key.
	APIKeySecretRef esmeta.SecretKeySelector `json:"apiKeySecretRef"`
}
