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
	"os"
	"strings"
)

// Environment variables the suite reads. Keys are never read from files or flags.
const (
	envServer       = "SIGMA_CONFIG_SERVER"
	envAPIKey       = "SIGMA_CONFIG_API_KEY"         // a Contributor key for the test organization
	envNoGrantKey   = "SIGMA_CONFIG_NOGRANT_API_KEY" // a key with no grant on the access-controlled project
	defaultE2EServe = "https://api.staging.cloudtruth.io"
)

type config struct {
	server     string
	apiKey     string
	noGrantKey string
}

// loadConfig returns the suite configuration and, when a key is missing, the reason to skip.
func loadConfig() (*config, string) {
	cfg := &config{
		server:     strings.TrimRight(os.Getenv(envServer), "/"),
		apiKey:     os.Getenv(envAPIKey),
		noGrantKey: os.Getenv(envNoGrantKey),
	}
	if cfg.server == "" {
		cfg.server = defaultE2EServe
	}
	var missing []string
	if cfg.apiKey == "" {
		missing = append(missing, envAPIKey)
	}
	if cfg.noGrantKey == "" {
		missing = append(missing, envNoGrantKey)
	}
	if len(missing) > 0 {
		return nil, "sigmaconfig e2e skipped: set " + strings.Join(missing, " and ") + " to run it against a Sigma Config test organization"
	}
	return cfg, ""
}
