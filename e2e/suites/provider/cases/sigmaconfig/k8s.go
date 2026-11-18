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
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/external-secrets/external-secrets-e2e/framework"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"

	//nolint
	. "github.com/onsi/ginkgo/v2"
	//nolint
	. "github.com/onsi/gomega"
)

const (
	keySecretName = "sigma-config-api-key"
	keySecretKey  = "api-key"
	storeName     = "sigma-config"
	targetName    = "target"
	esName        = "sigma-config-es"

	syncTimeout = 2 * time.Minute
	poll        = 2 * time.Second
	// createTimeout covers ESO's admission webhooks starting up: right after a fresh install
	// they can reject requests until their CA certificate is in place.
	createTimeout = time.Minute
)

// mustCreate creates obj, retrying while the API server refuses it (for example while the
// webhooks are not ready yet). AlreadyExists means an earlier attempt went through.
func mustCreate(f *framework.Framework, obj client.Object) {
	Eventually(func() error {
		err := f.CRClient.Create(GinkgoT().Context(), obj)
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}, createTimeout, poll).Should(Succeed(), "creating %T %q", obj, obj.GetName())
}

// storeOpts describes the SecretStore a case needs.
type storeOpts struct {
	project     string
	environment string
	tag         string
	apiKey      string
}

func createStore(f *framework.Framework, cfg *config, o storeOpts) {
	mustCreate(f, &corev1.Secret{
		Name: keySecretName, Namespace: f.Namespace.Name,
		StringData: map[string]string{keySecretKey: o.apiKey},
	})
	mustCreate(f, &esv1.SecretStore{
		Name: storeName, Namespace: f.Namespace.Name,
		Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{SigmaConfig: &esv1.SigmaConfigProvider{
			Server:      cfg.server,
			Project:     o.project,
			Environment: o.environment,
			Tag:         o.tag,
			Auth: esv1.SigmaConfigAuth{
				APIKeySecretRef: esmeta.SecretKeySelector{Name: keySecretName, Key: keySecretKey},
			},
		}}},
	})
}

func createExternalSecret(f *framework.Framework, data []esv1.ExternalSecretData, dataFrom []esv1.ExternalSecretDataFromRemoteRef, policy esv1.ExternalSecretDeletionPolicy, refresh time.Duration) {
	if policy == "" {
		policy = esv1.DeletionPolicyRetain
	}
	if refresh == 0 {
		refresh = time.Hour
	}
	mustCreate(f, &esv1.ExternalSecret{
		Name: esName, Namespace: f.Namespace.Name,
		Spec: esv1.ExternalSecretSpec{
			RefreshInterval: &metav1.Duration{Duration: refresh},
			SecretStoreRef:  esv1.SecretStoreRef{Name: storeName, Kind: esv1.SecretStoreKind},
			Target:          esv1.ExternalSecretTarget{Name: targetName, DeletionPolicy: policy},
			Data:            data,
			DataFrom:        dataFrom,
		},
	})
}

func dataRef(secretKey, key, property, version string) esv1.ExternalSecretData {
	return esv1.ExternalSecretData{
		SecretKey: secretKey,
		RemoteRef: esv1.ExternalSecretDataRemoteRef{Key: key, Property: property, Version: version},
	}
}

// waitForSecret polls the target Secret until match accepts its data. Values are never
// passed to Gomega, so a failure prints no secret.
func waitForSecret(f *framework.Framework, timeout time.Duration, what string, match func(map[string][]byte) bool) {
	Eventually(func() bool {
		var s corev1.Secret
		err := f.CRClient.Get(GinkgoT().Context(), types.NamespacedName{Namespace: f.Namespace.Name, Name: targetName}, &s)
		return err == nil && match(s.Data)
	}, timeout, poll).Should(BeTrue(), "target Secret never matched: "+what)
}

// secretStays checks that the target Secret keeps matching for the whole duration.
func secretStays(f *framework.Framework, d time.Duration, what string, match func(map[string][]byte) bool) {
	Consistently(func() bool {
		var s corev1.Secret
		err := f.CRClient.Get(GinkgoT().Context(), types.NamespacedName{Namespace: f.Namespace.Name, Name: targetName}, &s)
		return err == nil && match(s.Data)
	}, d, poll).Should(BeTrue(), "target Secret changed: "+what)
}

func updateExternalSecret(f *framework.Framework, mutate func(*esv1.ExternalSecret)) {
	Eventually(func() error {
		var es esv1.ExternalSecret
		if err := f.CRClient.Get(GinkgoT().Context(), types.NamespacedName{Namespace: f.Namespace.Name, Name: esName}, &es); err != nil {
			return err
		}
		mutate(&es)
		return f.CRClient.Update(GinkgoT().Context(), &es)
	}, syncTimeout, poll).Should(Succeed())
}

// equalTo compares without printing either side.
func equalTo(want *string) func([]byte) bool {
	return func(got []byte) bool { return want != nil && bytes.Equal(got, []byte(*want)) }
}

func waitStoreNotReady(f *framework.Framework) {
	Eventually(func() bool {
		var s esv1.SecretStore
		if err := f.CRClient.Get(GinkgoT().Context(), types.NamespacedName{Namespace: f.Namespace.Name, Name: storeName}, &s); err != nil {
			return false
		}
		for _, c := range s.Status.Conditions {
			if c.Type == esv1.SecretStoreReady && c.Status == corev1.ConditionFalse {
				return true
			}
		}
		return false
	}, syncTimeout, poll).Should(BeTrue(), "SecretStore never reported Ready=False")
}

func waitExternalSecretFailed(f *framework.Framework) {
	Eventually(func() bool {
		var es esv1.ExternalSecret
		if err := f.CRClient.Get(GinkgoT().Context(), types.NamespacedName{Namespace: f.Namespace.Name, Name: esName}, &es); err != nil {
			return false
		}
		for _, c := range es.Status.Conditions {
			if c.Type == esv1.ExternalSecretReady && c.Status == corev1.ConditionFalse && c.Reason == esv1.ConditionReasonSecretSyncedError {
				return true
			}
		}
		return false
	}, syncTimeout, poll).Should(BeTrue(), "ExternalSecret never reported a sync error")
}

// waitForControllerLog waits until an ESO controller log line written after since contains every
// part. ESO keeps provider errors out of conditions and events (they may carry payloads from
// other providers), so the provider's message is checked where users read it: the controller log.
func waitForControllerLog(f *framework.Framework, since time.Time, parts ...string) {
	Eventually(func() bool {
		return controllerLogContains(f, since, parts...)
	}, syncTimeout, poll).Should(BeTrue(), "no controller log line contains "+strings.Join(parts, " + "))
}

func controllerLogContains(f *framework.Framework, since time.Time, parts ...string) bool {
	ctx := GinkgoT().Context()
	pods, err := f.KubeClientSet.CoreV1().Pods("default").List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/instance=eso,app.kubernetes.io/name=external-secrets",
	})
	if err != nil {
		return false
	}
	sinceTime := metav1.NewTime(since)
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, con := range pod.Spec.Containers {
			if logContains(ctx, f, pod.Name, con.Name, &sinceTime, parts) {
				return true
			}
		}
	}
	return false
}

func logContains(ctx context.Context, f *framework.Framework, pod, container string, since *metav1.Time, parts []string) bool {
	rc, err := f.KubeClientSet.CoreV1().Pods("default").GetLogs(pod, &corev1.PodLogOptions{Container: container, SinceTime: since}).Stream(ctx)
	if err != nil {
		return false
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, 16<<20))
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		all := true
		for _, p := range parts {
			if !strings.Contains(line, p) {
				all = false
				break
			}
		}
		if all && f.Namespace != nil && strings.Contains(line, f.Namespace.Name) {
			return true
		}
	}
	return false
}
