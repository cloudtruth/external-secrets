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
	"time"

	"github.com/external-secrets/external-secrets/providers/v1/sigmaconfig/api"
)

const (
	// ProviderSigmaConfig is the provider label of the API call metrics.
	ProviderSigmaConfig = "SigmaConfig"

	// CallProjectLookup labels project-by-name lookups.
	CallProjectLookup = api.CallProjectLookup
	// CallEnvironmentLookup labels environment-by-name lookups (Validate only).
	CallEnvironmentLookup = api.CallEnvironmentLookup
	// CallTagLookup labels tag lookups (Validate only).
	CallTagLookup = api.CallTagLookup
	// CallParameterList labels parameter list requests, bulk and by-name.
	CallParameterList = api.CallParameterList

	defaultServer      = "https://api.cloudtruth.io"
	defaultEnvironment = "default"

	requestTimeout  = 30 * time.Second
	validateTimeout = 30 * time.Second
)
