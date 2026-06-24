# GKE connector

**Connector id:** `gke`
**Scope:** Kubernetes API requests to Google Kubernetes Engine clusters.

## Quick start

Run Cynative from an environment where Google Application Default Credentials are available. Discover the cluster endpoint through the [GCP connector](gcp.md) first, then use the GKE connector for Kubernetes API requests.

## Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | the cluster's live configured ClusterRole (default `view`; allow-only RBAC), via kube-apiserver-style request classification — see [kubernetes.md](kubernetes.md) |
| Configurable exposure | ✓ · `connectors.gke.cluster_role` selects the authorization ClusterRole (default `view`); see [kubernetes.md](kubernetes.md#configuration) |
| Credential downscoping | — · Kubernetes decouples authn from authz; no client-side downscoping primitive |
| Host pinning | ✓ (cluster endpoint from the GKE Container API) |
| Dial-time IP authorization | ✓ (IP-literal endpoint only; DNS-based control-plane endpoints fail closed) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Credential discovery

### Credential sources

The GKE connector reuses the same Google ADC token source as the [GCP connector](gcp.md) for Kubernetes bearer tokens. The ADC variables are consumed by Google's credential libraries, not by cynative directly (cynative reads these only as a startup presence signal):

- `GOOGLE_APPLICATION_CREDENTIALS` — path to a credential JSON; the GCP identity ADC discovers (first ADC source).
- `APPDATA` — on Windows only, locates the well-known gcloud ADC file (`%APPDATA%\gcloud\application_default_credentials.json`).

See the [gcp connector](gcp.md) for the full ADC chain and project/config variables.

### Registration and validation

The GKE connector registers together with the `gcp` connector, gated on the same eager ADC probe: cynative finds ADC and then mints a test cloud-platform token, registering both only if that succeeds (see the [gcp connector](gcp.md#credential-discovery)). An ADC source that exists but cannot mint a token — for example a revoked `gcloud` ADC refresh token — leaves GKE **unavailable at startup**, not failing only on the first request.

### References

- [How Application Default Credentials works](https://docs.cloud.google.com/docs/authentication/application-default-credentials) — the ADC search order that decides GKE identity.

## Target selection

### Default target

None — the GKE connector has no default cluster. The identity comes from the same ADC chain as the [gcp connector](gcp.md); the target cluster is named per request via `gke_auth` (`project` + `location` + `cluster_name`, all required), and cynative resolves its endpoint host and CA from the GKE Container API and pins the request to it — a DNS-based control-plane endpoint is not IP-pinnable and fails closed (only IP-literal endpoints are supported).

### Change the target

Change the identity via the ADC mechanisms the [gcp connector](gcp.md) documents (`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or an attached service account). Change the target cluster by supplying different `gke_auth.project` / `gke_auth.location` / `gke_auth.cluster_name` per request — there is no cynative or vendor default-cluster setting (the vendor analog for the triple is `gcloud container clusters get-credentials CLUSTER_NAME --location=LOCATION --project=PROJECT`). To select the read-only authorization ClusterRole, set `connectors.gke.cluster_role` (see [Cynative configuration](#cynative-configuration)).

### Targeting inputs

The target cluster comes from the per-request `gke_auth` object — `gke_auth.project`, `gke_auth.location`, and `gke_auth.cluster_name` (all required); see [Request usage](#request-usage) for the full schema.

- [Configure cluster access for kubectl (GKE)](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl) — `gcloud container clusters get-credentials CLUSTER_NAME --location=LOCATION` (maps to the `gke_auth` triple); `--dns-endpoint` (cynative fails closed on DNS endpoints) and `--internal-ip`.

## Request usage

### Required `http_request` args

Use `auth_provider: "gke"` and include:

```json
{
  "gke_auth": {
    "project": "my-project",
    "location": "us-central1",
    "cluster_name": "prod"
  }
}
```

`gke_auth.project`, `gke_auth.location`, and `gke_auth.cluster_name` are all required.

### Minimal example

```js
const resp = await http_request({
  method: "GET",
  url: "https://34.71.1.2/api",
  headers: [],
  body: "",
  auth_provider: "gke",
  gke_auth: { project: "my-project", location: "us-central1", cluster_name: "prod" }
});
console.log(resp.body);
```

## Hardening

GKE is one of the managed Kubernetes connectors built on the shared, read-oriented Kubernetes API model. The connector contributes the GKE-specific cluster facts; the per-request authorization, comparison to read-only Kubernetes MCP servers, and the full security model live in [kubernetes.md](kubernetes.md). In request order, before any request is sent:

- **Host pinning.** Cynative fetches the cluster endpoint and CA data through the GKE Container API and pins the request host to that authoritative endpoint. A request whose host is not the resolved endpoint is rejected.
- **Kubernetes action authorization.** Each request is classified the way the kube-apiserver classifies it and authorized against the cluster's live `view` ClusterRole (allow-only RBAC), failing closed when the policy cannot be resolved — the shared model in [kubernetes.md](kubernetes.md).
- **Credential injection.** Cynative attaches the ADC bearer token only after host and action authorization pass. Model-supplied credentials are rejected before injection: a request carrying an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fails closed.
- **Dial-time IP authorization.** The transport's dial guard authorizes the resolved IP before connecting. The GKE endpoint reported by the Container API must be an IP literal, which the guard pins to; a DNS-based control-plane endpoint is not IP-pinnable and fails closed (see Limitations).

## Cynative configuration

### Exposure & authorization settings

The read-only ClusterRole this connector authorizes against is configurable
(default `view`); see the [shared Kubernetes model](kubernetes.md#configuration)
for the widening warning.

```yaml
connectors:
  gke:
    cluster_role: view   # env CYNATIVE_CONNECTORS_GKE_CLUSTER_ROLE
```

## Limitations

- The connector depends on ADC credentials that can call the GKE Container API to resolve the cluster endpoint and CA data.
- The model must first discover or verify the cluster endpoint. The connector verifies the endpoint it is given but does not guess the URL — discover it through the [GCP connector](gcp.md) first.
- **DNS-based GKE control-plane endpoints fail closed.** A [DNS-based control-plane endpoint](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation) resolves to shared Google Front End (GFE) infrastructure rather than a stable per-cluster IP, so it is not IP-pinnable; the dial-time guard rejects it. Use a cluster whose endpoint is an IP literal.
- There is no client-side credential downscoping for GKE. Kubernetes decouples authentication from authorization — a bearer token only authenticates the caller, and authorization is server-side RBAC ([Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)) — so the in-process `view` gate, host pinning, and dial-time IP authorization are the only client-side controls.
- For the shared authorization model, host/address controls, TLS material, and the comparison to read-only Kubernetes MCP servers, see [kubernetes.md](kubernetes.md).
