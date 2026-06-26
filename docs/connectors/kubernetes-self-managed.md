# Kubernetes (self-managed) connector

**Connector id:** `kubernetes`
**Scope:** Kubernetes API requests to self-managed clusters (k3s, kubeadm, k0s, on-prem, bare-metal, dev) that are not fronted by a cloud provider API.

## Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | the cluster's live configured ClusterRole (default `view`; allow-only RBAC), via kube-apiserver-style request classification — see [kubernetes.md](kubernetes.md) |
| Configurable exposure | ✓ · `connectors.kubernetes.cluster_role` selects the authorization ClusterRole (default `view`); see [kubernetes.md](kubernetes.md#configuration) |
| Credential downscoping | — · Kubernetes decouples authn from authz; no client-side downscoping primitive |
| Host pinning | ✓ (kubeconfig cluster `server`) |
| Dial-time IP authorization | ✓ (exact IP for an IP-literal server, resolved set for an FQDN; RFC1918 private ranges allowed) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Quick start

Run Cynative from an environment with a working kubeconfig for the target cluster (the same one `kubectl` uses). The connector reads the kubeconfig, selects the current context, and uses it for Kubernetes API requests.

## Setup prerequisites

Cynative's Kubernetes hardening derives its allow-policy from a ClusterRole fetched live from the target cluster — the configured ClusterRole (default `view`), fetched at `GET /apis/rbac.authorization.k8s.io/v1/clusterroles/<name>`. The configured identity must therefore be allowed to **read that ClusterRole**, or Cynative fails closed and denies every request (`reading clusterrole "view" returned k8s API 403 Forbidden; the identity is authenticated but not authorized to read it`).

This matters specifically for self-managed clusters because operators often bind a minimal identity directly to `view` — but the upstream `view` role does **not** include `get clusterroles` (it grants reads on most namespaced resources and a few cluster-scoped ones, but not ClusterRoles themselves), so a `view`-only identity cannot read its own policy source. Grant the identity read access to the chosen ClusterRole explicitly (the example below uses the default `view`):

```yaml
# Allow the connector identity to read the view ClusterRole (and only that).
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cynative-read-view-role
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    resourceNames: ["view"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cynative-read-view-role
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cynative-read-view-role
subjects:
  - kind: ServiceAccount
    name: <your-connector-serviceaccount>
    namespace: <its-namespace>
```

In practice a cloud connector's discovered credentials often already carry the needed read access, so this prerequisite most often affects hand-crafted self-managed identities. (All four Kubernetes connectors use the same `view`-role fetch path.)

## Credential discovery and eager validation

### Credential sources

The connector discovers the kubeconfig exactly as `kubectl` does and reads only safe, static fields:

- `KUBECONFIG` — a list of kubeconfig files client-go loads and merges (colon-separated on Unix, semicolon-separated on Windows) before falling back to `~/.kube/config`; the sole targeting/discovery signal. Cynative also reads it as the explicit-selection signal for loud-vs-quiet skip diagnostics.

It selects the `current-context` and supports exactly two credential modes:

- **Static bearer token** — `users[].user.token`, or `users[].user.tokenFile` (re-read per request, so a rotated ServiceAccount token is picked up).
- **Client certificate (mTLS)** — `users[].user.client-certificate[-data]` plus `users[].user.client-key[-data]`.

The connector **fails closed and is not registered** when the selected context uses any of: an `exec` credential plugin, an `auth-provider` plugin, impersonation, basic-auth username/password, `insecure-skip-tls-verify: true`, a `proxy-url`, a non-`https` server, a server URL with embedded credentials, or supplies no usable bearer/client-cert credential. The skip reason is logged only when the kubeconfig is explicitly selected (`$KUBECONFIG` set) or under `--verbose`; an ambient `~/.kube/config` context is skipped quietly. This means a typical **cloud** kubeconfig context (GKE/EKS/AKS use `exec` plugins such as `gke-gcloud-auth-plugin`) is intentionally rejected — use the dedicated `eks`, `gke`, or `aks` connectors for those clusters.

### Registration and validation

After parsing the kubeconfig and building the provider, Cynative **eagerly validates the cluster at startup** before registering. It performs a single dial-guarded `GET /apis/rbac.authorization.k8s.io/v1/clusterroles/<configured-role>` fetch — the same host-pinned, IP-pinned path used at request time — and registers only if the cluster is reachable **and** the fetch succeeds. A cluster that cannot be reached, or whose configured identity lacks permission to read the ClusterRole, becomes **unavailable** with a reason (`cluster validation failed: …`). Whether that skip is shown follows the same emit policy as the cloud connectors' skips: it is shown (loud) when the kubeconfig is explicitly selected (`$KUBECONFIG` set), under `--verbose`, or on a transient error; an ambient validation failure (no explicit kubeconfig) is quiet. A transient error — a network timeout **or** an HTTP 429/5xx from the cluster API — is retried once.

The eager probe is **validation only**: the policy is not cached from it. On the first real `http_request` the ClusterRole is re-fetched and cached in memory as usual, so a rotated token or a temporary network blip between startup and first use does not break the session.

This contrasts with the managed connectors (`eks`, `gke`, `aks`), whose validation is gated on the parent-cloud credential (AWS/GCP/Azure): those connectors do not probe the Kubernetes API at registration; they register when the parent cloud credential validates, and the Kubernetes API is validated on the first request.

### References

- [Organizing cluster access using kubeconfig files](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) — `KUBECONFIG` (merged file list, OS-specific separator), the default `~/.kube/config`, and `current-context`.
- [kubectl config use-context](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_config/kubectl_config_use-context/) — the command to switch which cluster this connector targets.

## Target selection

### Default target

The single Kubernetes cluster named by the local kubeconfig's `current-context`. There is no Cynative-level override — the connector targets the one cluster the selected context names.

### Change the target

To target a different file, set `$KUBECONFIG`; to select a different context, run `kubectl config use-context <name>` — the same mechanisms `kubectl` uses, and cynative adds no override. Cloud-style contexts that use `exec` / `auth-provider` plugins are rejected fail-closed (see [Credential discovery](#credential-discovery-and-eager-validation)) — use the [eks](eks.md) / [gke](gke.md) / [aks](aks.md) connectors for those. To change the read-only authorization ClusterRole (not the target), set `connectors.kubernetes.cluster_role` (see [Cynative configuration](#cynative-configuration)).

### Targeting inputs

`auth_provider: "kubernetes"` with an empty `kubernetes_auth` object — there is no per-request cluster selector, and the request host must match the kubeconfig cluster `server`. See [Request usage](#request-usage) for the call shape.

### TLS server name (IP endpoints with DNS-only certificates)

When the cluster endpoint is an IP literal but its CA-issued serving certificate has only DNS Subject Alternative Names (no IP SAN), set `clusters[].cluster.tls-server-name` in the kubeconfig (as you would for `kubectl`). Cynative honors it: the dial stays pinned to the IP, while TLS verification uses the configured server name. If the serving certificate already includes the endpoint IP in its SANs (e.g. a k3s server started with `--tls-san <IP>`), no `tls-server-name` is needed.

## Request usage

### Required `http_request` args

Use `auth_provider: "kubernetes"`. `kubernetes_auth` is optional (and empty) — the connector targets the single configured cluster:

```json
{
  "kubernetes_auth": {}
}
```

### Minimal example

```js
const resp = await http_request({
  method: "GET",
  url: "https://203.0.113.10:6443/api/v1/namespaces/default/pods",
  headers: [],
  body: "",
  auth_provider: "kubernetes",
  kubernetes_auth: {}
});
console.log(resp.body);
```

## Hardening

- Cynative reads the cluster endpoint, CA, and credential from the local kubeconfig — never from a cloud API and never by executing an exec plugin.
- The request host must equal the configured cluster endpoint host.
- The dialed IP must pass the shared forbidden-address floor (loopback, link-local, cloud metadata, IPv6 ULA are always rejected) and then match the endpoint pin: an IP-literal endpoint pins to that exact address; an FQDN endpoint is re-resolved per dial and the dialed IP must be in the resolved set. RFC1918 private addresses are allowed (on-prem clusters legitimately use them); the configured endpoint is the per-cluster allow.
- Model-supplied credentials are rejected before injection: requests carrying an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fail closed.
- Cynative attaches the bearer token (or presents the client certificate for mTLS) only after host and Kubernetes action authorization pass; the dial guard still authorizes the resolved IP before the request is sent.
- Kubernetes API authorization uses the shared [Kubernetes connector hardening](kubernetes.md) model (the configured ClusterRole, default `view`; fail-closed). That page also covers the per-request classification flow and how this posture compares to read-only Kubernetes MCP servers, so this page does not repeat them.

## Cynative configuration

### Exposure & authorization settings

The authorization ClusterRole is configurable (default `view`):

```yaml
connectors:
  kubernetes:
    cluster_role: view   # or a custom read-only ClusterRole; env CYNATIVE_CONNECTORS_KUBERNETES_CLUSTER_ROLE
```

The configured identity must be able to read whichever ClusterRole you select
(`get clusterroles/<name>`). Widening it past `view` widens Cynative's permitted
verbs — see the [shared model](kubernetes.md#configuration).

The configured ClusterRole is shown in the startup connector inventory, for example:

```text
✓ k8s    access=default(read-only) · enforced=client · cluster role=view · cluster-host
```

- `access=default(read-only)` when `connectors.kubernetes.cluster_role` is `view`; `access=custom` for any other ClusterRole.
- `enforced=client` — Kubernetes decouples authn from authz; the in-process ClusterRole-based authorization check is the sole client-side control.
- `cluster role=<name>` — the configured ClusterRole verbatim.

Operators can confirm the authorization policy in force at a glance.

## Limitations

- The gate trusts the fetched role. Cynative enforces *exactly* the
  rules of the configured ClusterRole (default `view`) and adds no independent
  mutation-verb floor. Kubernetes' built-in `view` is an **aggregated** role
  (`rbac.authorization.k8s.io/aggregate-to-view`), so if an administrator (or an
  installed controller) has aggregated write rules into `view`, Cynative would
  honor them. For least privilege, point the connector at a dedicated,
  non-aggregated read-only ClusterRole via `connectors.<eks|gke|aks|kubernetes>.cluster_role`.

- The configured identity must be able to read the configured ClusterRole (default `view`) — see [Setup prerequisites](#setup-prerequisites) above; a `view`-only identity cannot read `clusterroles/view`, and Cynative then fails closed.
- Cynative's gate enforces exactly what the configured ClusterRole grants. The default upstream `view` role intentionally does **not** grant reading Secrets — per the [Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), reading Secret contents "enables access to ServiceAccount credentials in the namespace, which would allow API access as any ServiceAccount in the namespace (a form of privilege escalation)" — and grants no write verbs, though it does permit a broad set of reads (including some cluster-scoped reads such as listing namespaces). Selecting a wider role widens the enforced surface — see [Configuration](kubernetes.md#configuration).
- Only static bearer-token and client-certificate (mTLS) credentials are supported. Exec credential plugins and auth-provider plugins are deliberately not honored (arbitrary local code execution risk); `insecure-skip-tls-verify` and `proxy-url` are rejected.
- One cluster per run (the selected context). Multi-cluster selection is not supported in this version.
- Credential rotation: a bearer `tokenFile` is re-read per request, but a rotated literal `token` or rotated client certificate requires re-running Cynative (the kubeconfig is read once at startup).
- For an HA control plane behind a rotating DNS endpoint, the dial guard re-resolves per dial and pins to the resolved set; if backend IPs rotate between resolution and connect, a dial may be rejected (fail-closed). Prefer an IP-literal endpoint or a stable DNS name.
- File-referenced CA/token/certificate paths in the kubeconfig are read with the operator's own privileges and sent only to the pinned cluster endpoint — the same posture as `kubectl`.
