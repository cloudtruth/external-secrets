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

// Package sigmaconfig runs the Sigma Config provider against a live Sigma Config test
// organization. It needs SIGMA_CONFIG_API_KEY and SIGMA_CONFIG_NOGRANT_API_KEY and skips
// without them, so it is not part of ESO's CI. Expected values are read from the API at run
// time and compared without being printed; no seed value is written into this file.
package sigmaconfig

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"time"

	//nolint
	. "github.com/onsi/ginkgo/v2"
	//nolint
	. "github.com/onsi/gomega"

	"github.com/external-secrets/external-secrets-e2e/framework"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

const (
	payments     = "payments-api"
	templateErrs = "template-errors"
	restricted   = "restricted-ledger"
	production   = "production"
	development  = "development"
	oldTag       = "release-2026-09"
)

var _ = Describe("[sigmaconfig]", Label("sigmaconfig"), Ordered, func() {
	f := framework.New("eso-sigmaconfig")
	var (
		cfg *config
		api *apiClient
	)

	BeforeAll(func() {
		var reason string
		cfg, reason = loadConfig()
		if cfg == nil {
			Skip(reason)
		}
		api = newAPIClient(cfg.server, cfg.apiKey)
	})

	expect := func(project, environment, tag, name string) *string {
		v, err := api.expected(GinkgoT().Context(), project, environment, tag, name)
		Expect(err).ToNot(HaveOccurred())
		Expect(v).ToNot(BeNil(), "seed parameter "+name+" has no value in "+environment)
		return v
	}

	singleKey := func(id, name string) {
		It(id+": reads "+name, func() {
			want := expect(payments, production, "", name)
			createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
			createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", name, "", "")}, nil, "", 0)
			waitForSecret(f, syncTimeout, name, func(d map[string][]byte) bool { return equalTo(want)(d["value"]) })
		})
	}

	singleKey("P-01 value set in the environment", "db_password")
	singleKey("P-02 inherited from the parent environment", "region")
	singleKey("P-03 inherited from the dependency project", "shared_api_token")
	singleKey("P-04 child project override wins", "log_level")

	It("P-05: reads one property of a JSON value", func() {
		raw := expect(payments, production, "", "stripe")
		var obj map[string]any
		Expect(json.Unmarshal([]byte(*raw), &obj)).To(Succeed(), "stripe is not a JSON object")
		field, ok := obj["secret_key"].(string)
		Expect(ok).To(BeTrue(), "stripe has no string field secret_key")
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "stripe", "secret_key", "")}, nil, "", 0)
		waitForSecret(f, syncTimeout, "stripe.secret_key", func(d map[string][]byte) bool { return equalTo(&field)(d["value"]) })
	})

	It("P-06: extracts every field of a JSON value", func() {
		raw := expect(payments, production, "", "stripe")
		var obj map[string]json.RawMessage
		Expect(json.Unmarshal([]byte(*raw), &obj)).To(Succeed(), "stripe is not a JSON object")
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, nil, []esv1.ExternalSecretDataFromRemoteRef{{Extract: &esv1.ExternalSecretDataRemoteRef{Key: "stripe"}}}, "", 0)
		waitForSecret(f, syncTimeout, "one key per stripe field", func(d map[string][]byte) bool {
			if len(d) != len(obj) {
				return false
			}
			for k, v := range obj {
				var s string
				want := []byte(v)
				if json.Unmarshal(v, &s) == nil {
					want = []byte(s)
				}
				if !bytes.Equal(d[k], want) {
					return false
				}
			}
			return true
		})
	})

	It("P-07: names a parameter whose template fails, via the by-name fallback", func() {
		start := time.Now()
		createStore(f, cfg, storeOpts{project: templateErrs, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "pool_size", "", "")}, nil, "", 0)
		waitExternalSecretFailed(f)
		waitForControllerLog(f, start, `parameter \"pool_size\"`, "failed to evaluate")
	})

	It("P-08: a parameter with no value in the environment is missing, not empty", func() {
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{
			dataRef("present", "db_password", "", ""),
			dataRef("absent", "dev_only", "", ""),
		}, nil, esv1.DeletionPolicyDelete, 0)
		waitForSecret(f, syncTimeout, "present only", func(d map[string][]byte) bool {
			_, absent := d["absent"]
			return len(d["present"]) > 0 && !absent
		})
	})

	It("P-09: reads a value at a tag through remoteRef.version", func() {
		want := expect(payments, production, oldTag, "feature_flags")
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "feature_flags", "", oldTag)}, nil, "", 0)
		waitForSecret(f, syncTimeout, "feature_flags at "+oldTag, func(d map[string][]byte) bool { return equalTo(want)(d["value"]) })
	})

	It("P-10: an unknown store tag makes the store not ready and is named", func() {
		start := time.Now()
		createStore(f, cfg, storeOpts{project: payments, environment: production, tag: "no-such-tag", apiKey: cfg.apiKey})
		waitStoreNotReady(f)
		waitForControllerLog(f, start, `tag \"no-such-tag\" not found`)
	})

	It("P-11: a key without a grant cannot see an access-controlled project", func() {
		start := time.Now()
		createStore(f, cfg, storeOpts{project: restricted, environment: production, apiKey: cfg.noGrantKey})
		waitStoreNotReady(f)
		waitForControllerLog(f, start, "not found or not visible to this API key")
	})

	It("P-12: finds parameters by name regexp", func() {
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, nil, []esv1.ExternalSecretDataFromRemoteRef{{Find: &esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^db_"}}}}, "", 0)
		wants := map[string]*string{}
		for _, name := range []string{"db_password", "db_url", "db_host"} {
			wants[name] = expect(payments, production, "", name)
		}
		re := regexp.MustCompile("^db_")
		waitForSecret(f, syncTimeout, "db_password, db_url, db_host", func(d map[string][]byte) bool {
			for k := range d {
				if !re.MatchString(k) {
					return false
				}
			}
			for name, want := range wants {
				if !equalTo(want)(d[name]) {
					return false
				}
			}
			return true
		})
	})

	It("P-13: a template is returned rendered", func() {
		want := expect(payments, production, "", "db_url")
		host := expect(payments, production, "", "db_host")
		Expect(bytes.Contains([]byte(*want), []byte(*host))).To(BeTrue(), "seed: db_url does not contain db_host")
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "db_url", "", "")}, nil, "", 0)
		waitForSecret(f, syncTimeout, "rendered db_url", func(d map[string][]byte) bool { return equalTo(want)(d["value"]) })
	})

	It("P-14: an integer parameter arrives as the exact string", func() {
		want := expect(payments, production, "", "max_connections")
		Expect(regexp.MustCompile(`^-?[0-9]+$`).MatchString(*want)).To(BeTrue(), "seed: max_connections is not an integer string")
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "max_connections", "", "")}, nil, "", 0)
		waitForSecret(f, syncTimeout, "max_connections", func(d map[string][]byte) bool { return equalTo(want)(d["value"]) })
	})

	It("P-15: a changed value reaches the Secret", func() {
		ctx := GinkgoT().Context()
		createStore(f, cfg, storeOpts{project: payments, environment: development, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "e2e_scratch", "", "")}, nil, esv1.DeletionPolicyDelete, 15*time.Second)

		newValue := "e2e-" + randomHex(8)
		Expect(api.setValue(ctx, payments, development, "e2e_scratch", newValue)).To(Succeed())
		// Staging can take minutes to recompute; then up to 30 s of provider cache and one refresh.
		waitForSecret(f, 5*time.Minute+30*time.Second+30*time.Second, "new e2e_scratch value", func(d map[string][]byte) bool {
			return equalTo(&newValue)(d["value"])
		})
	})

	It("P-16: a bad key makes the store not ready, and the key is not logged", func() {
		start := time.Now()
		badKey := "e2e" + randomHex(4) + "." + randomHex(24) // right shape, never issued
		createStore(f, cfg, storeOpts{project: payments, environment: production, apiKey: badKey})
		waitStoreNotReady(f)
		waitForControllerLog(f, start, "authentication failed (HTTP 401)")
		Expect(controllerLogContains(f, start, badKey)).To(BeFalse(), "the API key appears in the controller log")
	})

	It("P-17: a healthy key in a project with a broken template still syncs", func() {
		want := expect(templateErrs, production, "", "healthy_value")
		createStore(f, cfg, storeOpts{project: templateErrs, environment: production, apiKey: cfg.apiKey})
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "healthy_value", "", "")}, nil, "", 0)
		waitForSecret(f, syncTimeout, "healthy_value", func(d map[string][]byte) bool { return equalTo(want)(d["value"]) })
	})

	It("P-18: a bulk read that hits a broken template fails and leaves the Secret as it was", func() {
		want := expect(templateErrs, production, "", "healthy_value")
		createStore(f, cfg, storeOpts{project: templateErrs, environment: production, apiKey: cfg.apiKey})
		// First sync a Secret, then point the same ExternalSecret at a bulk read of the project.
		createExternalSecret(f, []esv1.ExternalSecretData{dataRef("value", "healthy_value", "", "")}, nil, "", 0)
		waitForSecret(f, syncTimeout, "healthy_value", func(d map[string][]byte) bool { return equalTo(want)(d["value"]) })

		updateExternalSecret(f, func(es *esv1.ExternalSecret) {
			es.Spec.Data = nil
			es.Spec.DataFrom = []esv1.ExternalSecretDataFromRemoteRef{{Find: &esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: ".*"}}}}
		})
		waitExternalSecretFailed(f)
		secretStays(f, 20*time.Second, "unchanged after the failed bulk read", func(d map[string][]byte) bool {
			return len(d) == 1 && equalTo(want)(d["value"])
		})
	})
})

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
