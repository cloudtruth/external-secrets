Sync parameters from [Sigma Config](https://sigma-automate.com/config) (formerly CloudTruth) to Kubernetes Secrets. Sigma Config stores configuration and secrets in projects and environments, with inheritance, templates and tags. The `sigmaconfig` provider reads parameters, secret or not, and writes them into Kubernetes Secrets.

The provider is read-only: it reads from Sigma Config and never writes to it. `PushSecret` is not supported.

## Store configuration

One SecretStore maps to one Sigma Config project in one environment, optionally pinned to one tag.

```yaml
{% include 'sigmaconfig-secret-store.yaml' %}
```

| Field | Required | Description |
|---|---|---|
| `server` | No | HTTPS URL of the Sigma Config API. Default `https://api.cloudtruth.io`. |
| `project` | Yes | Project name, case sensitive. |
| `environment` | No | Environment name. Default `default`. |
| `tag` | No | Tag name in that environment. Every read returns values as they were at the tag. |
| `auth.apiKeySecretRef` | Yes | Secret key selector for a Sigma Config API key. `namespace` is allowed only on a ClusterSecretStore. |
| `caBundle` | No | Base64-encoded PEM CA certificate to trust in addition to the system roots, for a `server` behind a private CA (for example a TLS-inspecting proxy). |
| `caProvider` | No | Reads the CA certificate from a Secret or ConfigMap instead of `caBundle`. |

### Authentication

Create a service account in Sigma Config for ESO, generate an API key for it, and store the key in a Kubernetes Secret:

```sh
kubectl create secret generic sigma-config-api-key --from-literal=api-key='<your API key>'
```

Live reads need a key with the **Contributor** role: an org role of Contributor or higher, plus a Contributor grant on any access-controlled project. Viewer and No Secrets keys can only read at a tag.

A Contributor key can read every project that is not access-controlled. Use a dedicated service account for ESO, and keep secrets that ESO should not reach in access-controlled projects.

## Fetching parameters

```yaml
{% include 'sigmaconfig-external-secret.yaml' %}
```

- `remoteRef.key` is the parameter name, matched exactly and case sensitively.
- Values are the final values Sigma Config resolves: inherited from parent environments and from projects this project depends on, with templates evaluated and external (AWS, Azure) references pulled.
- Integer and boolean parameters arrive as strings, for example `"25"`.
- `remoteRef.property` reads one field of a parameter whose value is JSON.
- `remoteRef.version` is a tag name. It overrides the store's `tag` for that key only.
- A parameter that does not exist, or has no value in the environment, is treated as missing, so `deletionPolicy` applies.

### Expanding a JSON parameter

`dataFrom.extract` turns each field of a JSON object parameter into its own Secret key:

```yaml
{% include 'sigmaconfig-extract.yaml' %}
```

### Fetching many parameters

`dataFrom.find.name.regexp` fetches every parameter whose name matches:

```yaml
{% include 'sigmaconfig-find.yaml' %}
```

Parameter names can contain characters Kubernetes Secret keys don't allow, such as spaces or slashes. Use ESO's [`rewrite`](../guides/datafrom-rewrite.md) to rename them.

`find.tags` and `find.path` are not supported: Sigma Config tags are points in time, not labels, and parameters have no paths.

If any parameter in the project fails to evaluate, a `find` read fails as a whole and the Secret keeps its previous data. Single-key reads of other parameters keep working.

## API budget

Each Sigma Config organization has a default budget of 5,000 API requests per hour, shared by every user, CLI, CI job and API key in it.

The provider fetches a whole project in one request per 1,000 parameters and caches it for 30 seconds, shared by every ExternalSecret that uses the same store. A store therefore costs at most about 120 requests per hour, plus up to 36 for ESO's store validation every 5 minutes, regardless of how many ExternalSecrets use it. Each distinct tag, including each per-key `version`, costs the same again.

Without that cache, the cost would be roughly:

```
requests per hour ≈ ExternalSecrets × 3,600 ÷ refreshInterval in seconds
```

so 50 ExternalSecrets at a 1 minute interval would use 3,000 requests per hour, 60% of the budget.

Recommendations:

- Use `refreshInterval: 5m` or longer.
- Intervals shorter than 30 seconds receive cached values.
- Share one store per project and environment rather than creating many.
- On a store shared by several teams, anyone who can create an ExternalSecret against it can spend the organization's budget, for example with many different `remoteRef.version` tags, each of which costs its own fetch. Limit who can use a `ClusterSecretStore` with its `conditions` (namespace selectors), and prefer one namespaced `SecretStore` per team.

## Errors

ESO shows a generic reason on the SecretStore or ExternalSecret status ("unable to validate store", "could not get secret data from provider"). The provider's detailed message is in the ESO controller logs:

```sh
kubectl logs -n external-secrets deploy/external-secrets | grep sigmaconfig
```

| Message in the controller log | Likely cause |
|---|---|
| `project not found or not visible to this API key` | Wrong project name, or the key's service account has no grant on an access-controlled project. |
| `authentication failed (HTTP 401)` | Wrong or revoked API key. |
| `permission denied (HTTP 403)` | The key's role is too low for live reads, or it lacks a grant. |
| `environment "..." not found`, `tag "..." not found in environment "..."` | The name doesn't exist. Tags belong to one environment. |
| `parameter "..." ... failed to evaluate in Sigma Config` | A template or validation error in that parameter. Fix it in Sigma Config. |
| `its external value could not be pulled` | Sigma Config could not read the parameter's external (AWS, Azure) reference. |
| `API rate limit is spent (HTTP 429, Retry-After: ...)` | The organization's API budget is spent. ESO retries on a later reconcile. |
| `request blocked before reaching Sigma Config` | The per-IP edge limit (3,000 requests per 5 minutes) was hit. |
