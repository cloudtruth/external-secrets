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
	"fmt"

	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/providers/v1/sigmaconfig/api"
)

var _ esv1.SecretsClient = &secretsClient{}

var errNotImplementedYet = errors.New("sigmaconfig: not implemented yet")

// secretsClient is a SecretsClient for one store. It is cheap: all state worth keeping lives in the
// process-wide caches, keyed by server, API key hash, project, environment and tag.
type secretsClient struct {
	api         *api.Client
	server      string
	keyHash     string
	keyRef      esmeta.SecretKeySelector
	project     string
	environment string
	tag         string

	snapshots  *snapshotCache
	projectIDs *projectIDCache
}

// GetSecret returns one parameter's value in the store's environment. remoteRef.version is a
// tag that overrides the store's tag for this key; remoteRef.property reads one field of a JSON value.
func (c *secretsClient) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	tag := c.tag
	if ref.Version != "" {
		tag = ref.Version
	}

	pv, err := c.lookup(ctx, tag, ref.Key)
	if err != nil {
		return nil, err
	}
	if pv == nil || pv.value == nil {
		return nil, esv1.NoSecretErr
	}
	if pv.externalError != "" {
		return nil, fmt.Errorf("sigmaconfig: parameter %q: its external value could not be pulled (error code %s)", ref.Key, pv.externalError)
	}

	value := *pv.value
	if ref.Property == "" {
		return []byte(value), nil
	}
	res := gjson.Get(value, ref.Property)
	if !res.Exists() {
		return nil, fmt.Errorf("sigmaconfig: property %q not found in parameter %q", ref.Property, ref.Key)
	}
	if res.Type == gjson.String {
		return []byte(res.Str), nil
	}
	return []byte(res.Raw), nil
}

// lookup finds one parameter in the bulk snapshot, falling back to a by-name read when the
// bulk read fails on a template error elsewhere in the project (FR-11).
func (c *secretsClient) lookup(ctx context.Context, tag, name string) (*paramValue, error) {
	snap := c.bulk(ctx, tag)
	if snap.err == nil {
		return snap.values[name], nil
	}
	if !isTemplateError(snap.err) {
		return nil, c.describe(snap.err, tag)
	}

	one := c.byName(ctx, tag, name)
	if one.err != nil {
		if isTemplateError(one.err) {
			return nil, templateError(c.project, c.environment, name)
		}
		return nil, c.describe(one.err, tag)
	}
	return one.values[name], nil
}

func (c *secretsClient) bulk(ctx context.Context, tag string) *snapshot {
	key := cacheKey("bulk", c.server, c.keyHash, c.project, c.environment, tag)
	return c.snapshots.get(key, func() *snapshot { return c.fetch(ctx, tag, "") })
}

func (c *secretsClient) byName(ctx context.Context, tag, name string) *snapshot {
	key := cacheKey("name", c.server, c.keyHash, c.project, c.environment, tag, name)
	return c.snapshots.get(key, func() *snapshot { return c.fetch(ctx, tag, name) })
}

// fetch lists parameters (all, or one by name) and indexes their values by name.
func (c *secretsClient) fetch(ctx context.Context, tag, name string) *snapshot {
	params, err := c.listParameters(ctx, tag, name)
	if err != nil {
		return &snapshot{err: err}
	}
	values := make(map[string]*paramValue, len(params))
	for _, p := range params {
		pv := &paramValue{}
		if v := p.ValueFor(c.environment); v != nil {
			pv.value = v.Value
			if v.ExternalStatus != nil {
				pv.externalError = v.ExternalStatus.ErrorCode
			}
		}
		values[p.Name] = pv
	}
	return &snapshot{values: values}
}

// listParameters resolves the project ID (cached) and lists parameters. If the cached ID no
// longer exists (renamed or deleted project), it is dropped and resolved once more.
func (c *secretsClient) listParameters(ctx context.Context, tag, name string) ([]api.Parameter, error) {
	id, err := c.projectID(ctx)
	if err != nil {
		return nil, err
	}
	params, err := c.api.ListParameters(ctx, id, c.environment, tag, name)
	var ae *api.Error
	if errors.As(err, &ae) && ae.IsObjectNotFound() {
		c.projectIDs.drop(c.projectIDKey())
		if id, err = c.projectID(ctx); err != nil {
			return nil, err
		}
		params, err = c.api.ListParameters(ctx, id, c.environment, tag, name)
	}
	return params, err
}

func (c *secretsClient) projectIDKey() string {
	return cacheKey(c.server, c.keyHash, c.project)
}

func (c *secretsClient) projectID(ctx context.Context) (string, error) {
	if id, ok := c.projectIDs.get(c.projectIDKey()); ok {
		return id, nil
	}
	id, found, err := c.api.ResolveProject(ctx, c.project)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errProjectNotVisible
	}
	c.projectIDs.set(c.projectIDKey(), id)
	return id, nil
}

// Validate checks that the key works and that the project, environment and tag exist.
func (c *secretsClient) Validate() (esv1.ValidationResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()

	if _, err := c.projectID(ctx); err != nil {
		if errors.Is(err, errProjectNotVisible) {
			return esv1.ValidationResultError, fmt.Errorf("sigmaconfig: project %q: %w", c.project, err)
		}
		return esv1.ValidationResultError, c.describe(err, c.tag)
	}
	envID, found, err := c.api.ResolveEnvironment(ctx, c.environment)
	if err != nil {
		return esv1.ValidationResultError, c.describe(err, c.tag)
	}
	if !found {
		return esv1.ValidationResultError, fmt.Errorf("sigmaconfig: environment %q not found", c.environment)
	}
	if c.tag != "" {
		ok, err := c.api.TagExists(ctx, envID, c.tag)
		if err != nil {
			return esv1.ValidationResultError, c.describe(err, c.tag)
		}
		if !ok {
			return esv1.ValidationResultError, fmt.Errorf("sigmaconfig: tag %q not found in environment %q", c.tag, c.environment)
		}
	}
	return esv1.ValidationResultReady, nil
}

// GetSecretMap is delivered in M3.
func (c *secretsClient) GetSecretMap(_ context.Context, _ esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return nil, errNotImplementedYet
}

// GetAllSecrets is delivered in M3.
func (c *secretsClient) GetAllSecrets(_ context.Context, _ esv1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, errNotImplementedYet
}

// PushSecret is not supported: the provider never writes to Sigma Config.
func (c *secretsClient) PushSecret(_ context.Context, _ *corev1.Secret, _ esv1.PushSecretData) error {
	return errReadOnly
}

// DeleteSecret is not supported: the provider never writes to Sigma Config.
func (c *secretsClient) DeleteSecret(_ context.Context, _ esv1.PushSecretRemoteRef) error {
	return errReadOnly
}

// SecretExists is not supported: it only serves PushSecret.
func (c *secretsClient) SecretExists(_ context.Context, _ esv1.PushSecretRemoteRef) (bool, error) {
	return false, errReadOnly
}

// Close is a no-op; the caches outlive the client by design.
func (c *secretsClient) Close(_ context.Context) error {
	return nil
}
