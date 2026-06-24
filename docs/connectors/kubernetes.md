# Kubernetes connector hardening

This is the shared Kubernetes API hardening model. The managed `eks`, `gke`, and `aks` connectors and the self-managed `kubernetes` connector all use it: they differ only in how they obtain a cluster's endpoint, CA data, and credential, then converge on the same per-request authorization, host pinning, dial-time IP authorization, and response redaction described here. The per-connector pages link back to this document for the security model; this page does not repeat their per-connector quick-starts.

The model is built for read-oriented Kubernetes API research. Every model-authored request to a cluster is classified the way the kube-apiserver classifies it and authorized against that cluster's own live read-only RBAC policy before any credential is attached and the connection is dialed.

## Defense at a glance

| Control | Status across eks / gke / aks / self-managed `kubernetes` |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | the cluster's live configured ClusterRole (default `view`; allow-only RBAC), applied per request via kube-apiserver-style request classification |
| Configurable exposure | ✓ · the authorization ClusterRole is operator-selectable per connector (default `view`); see [Configuration](#configuration) |
| Credential downscoping | — · Kubernetes decouples authentication from authorization, so there is no client-side credential-downscoping primitive — the in-process ClusterRole RBAC gate is the sole client-side control |
| Host pinning | ✓ (cloud-API endpoint, or kubeconfig server for self-managed) |
| Dial-time IP authorization | ✓ (EKS/AKS pin to the resolved endpoint IP set; GKE requires an IP-literal endpoint and fails closed on DNS-based endpoints; self-managed pins exact IP / resolved set and allows RFC1918) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Cluster targeting

These connectors do not share a single default cluster. The managed connectors ([eks](eks.md), [gke](gke.md), [aks](aks.md)) take their **target cluster** from per-request arguments (`eks_auth` / `gke_auth` / `aks_auth`) while inheriting **identity** from the underlying cloud credential chain (the [aws](aws.md), [gcp](gcp.md), and [azure](azure.md) connectors respectively). The self-managed [kubernetes](kubernetes-self-managed.md) connector instead targets the single cluster named by the local kubeconfig's current-context (`KUBECONFIG` / `~/.kube/config`), with no per-request selector. The authorization ClusterRole each connector enforces is operator-selectable via `connectors.<id>.cluster_role` (see [Configuration](#configuration)). Each connector's own page documents its exact targeting recipe in its **Target selection** section and its credential/environment details in **Credential discovery**.

## Shared authorization model

For each Kubernetes API request, Cynative runs the following sequence, in request order, before the request is sent:

- **Validate the cluster identity.** The connector first validates its connector-specific cluster-identity arguments (the EKS/GKE/AKS cluster facts, or the kubeconfig context for the self-managed `kubernetes` connector). A request that does not name a resolvable cluster identity is rejected before anything else happens.

- **Resolve and cache the cluster's configured ClusterRole policy.** Cynative fetches the target cluster's live ClusterRole — the operator-configured role, defaulting to the built-in `view` — once per cluster with `GET /apis/rbac.authorization.k8s.io/v1/clusterroles/<role>`, parses it into an allow-only RBAC policy, and caches it for the rest of the session. This bootstrap fetch is an internal call that bypasses the authorization gate to avoid a circular dependency; everything after it is authorized. The default `view` role is Kubernetes' own built-in read-only aggregate role, so by default the policy Cynative enforces is the cluster's own definition of "read-only," resolved live rather than hardcoded; see [Configuration](#configuration) to select a different role.

- **Classify the request the way the kube-apiserver does.** Cynative parses each request into a kube-apiserver-style `RequestInfo`: it decides whether the path is a resource request or a non-resource request, and for resource requests extracts the verb, API group, resource, subresource, namespace, and name. This is the same decomposition the apiserver uses to route authorization, so the classification Cynative authorizes against is the classification the cluster itself would apply.

- **Authorize the classified request against the configured ClusterRole policy.** A resource request is allowed only when it matches an allow rule in the resolved policy (verb against API group / resource / subresource). A non-resource request (for example `/version`, `/healthz`, or discovery paths) is allowed only when it is a GET or HEAD in a small, safe read-only allow-set. Anything that matches neither is denied.

- **Fail closed.** If the cluster's configured ClusterRole cannot be fetched or cannot be parsed into a policy, Cynative does not fall back to a permissive default — the request is denied. A cluster whose policy Cynative cannot resolve is a cluster Cynative will not call.

The net effect is that Cynative applies the cluster's own RBAC policy (read-only by default), client-side, to every individual API request, rather than reasoning about a fixed list of "safe" operations.

## Host and address controls

Two complementary controls bind a request to a known cluster endpoint: the request host is pinned to the authoritative endpoint, and the IP that host resolves to is authorized at dial time, before the TCP connection is established.

**Host pinning.** The managed connectors pin the request host to the authoritative cluster endpoint returned by the cloud-provider API (EKS, GKE, and AKS each report their own control-plane endpoint). The self-managed `kubernetes` connector pins the host to the kubeconfig cluster `server`, with no cloud-provider API dependency. A request whose host is not the pinned endpoint is rejected.

**Dial-time IP authorization.** The transport's dial guard authorizes the DNS-resolved IP before connecting, on every dial — including IP-literal targets — which closes DNS-rebinding and TOCTOU windows. The always-rejected floor set is:

- loopback,
- the unspecified address,
- link-local,
- link-local and interface-local multicast,
- IPv6 unique-local addresses (ULA),
- and known cloud host-local metadata addresses (for example Azure's WireServer `168.63.129.16` and the Alibaba metadata address `100.100.100.200`).

On top of that floor, each connector pins the dial to its endpoint:

- **EKS and AKS** resolve the authoritative endpoint hostname and require the dialed IP to be in that resolved endpoint IP set.
- **GKE** requires the endpoint reported by the GKE API to be an IP literal and pins to it; a DNS-based GKE control-plane endpoint is not IP-pinnable and fails closed.
- **Self-managed `kubernetes`** pins to the kubeconfig `server` — the exact IP for an IP-literal server, or the resolved set for an FQDN — and additionally allows RFC1918 private ranges, because on-prem and self-hosted clusters legitimately live on private networks.

## TLS material

EKS and GKE resolve cluster CA data from their cloud-provider APIs and supply it to the transport so the control-plane certificate is verified against the cluster's own CA. AKS resolves kubeconfig data from ARM and, depending on cluster configuration, can supply CA data, a client certificate, a client key, a bearer token, or an Entra ID bearer token. The self-managed `kubernetes` connector takes its CA and credential material directly from the local kubeconfig.

## How this compares to read-only Kubernetes MCP servers

Several Kubernetes MCP servers ship a read-only or non-destructive mode. They are useful guardrails, but each enforces "read-only" by gating which **tools** the model may call, client-side, before the request reaches the API:

- **[Flux159/mcp-server-kubernetes](https://github.com/Flux159/mcp-server-kubernetes)** offers `ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS=true`, which removes destructive tools (such as delete and cleanup) from the exposed toolset.
- **[containers/kubernetes-mcp-server](https://github.com/containers/kubernetes-mcp-server)** (Kubernetes / OpenShift) offers `--read-only` (no create/update/delete) and `--disable-destructive`, gating operations before the API call.
- **[Headlamp's MCP support](https://headlamp.dev/docs/latest/learn/mcp-support/)** documents no read-only mode.

Those approaches decide read-only by which tools are available. Cynative instead classifies each Kubernetes API request the way the kube-apiserver does and authorizes it against the cluster's live configured ClusterRole (default `view`) RBAC policy, per request — the cluster's own policy rather than a fixed tool list — and fails closed when that role cannot be resolved. Cynative additionally pins the request host and authorizes the dialed IP, so the credential cannot be steered to an unexpected endpoint.

None of these tools — Cynative included — downscopes the cluster credential. Kubernetes decouples authentication from authorization: a bearer token or client certificate only authenticates the caller, and authorization is performed server-side by the cluster's RBAC. Server-side RBAC therefore remains the authoritative authorization layer in every case; the client-side controls described here are a complementary in-process gate, not a replacement for it.

> Third-party behavior was checked against official docs/repos in June 2026; these tools change quickly, so re-verify before relying on this.

## Configuration

Each Kubernetes connector derives its read-only allow-policy from a ClusterRole
fetched live from the target cluster. The role is configurable per connector
(default `view`), mirroring `connectors.aws.policy` / `connectors.gcp.role` /
`connectors.azure.role_definition`:

```yaml
connectors:
  eks:        { cluster_role: view }   # CYNATIVE_CONNECTORS_EKS_CLUSTER_ROLE
  gke:        { cluster_role: view }   # CYNATIVE_CONNECTORS_GKE_CLUSTER_ROLE
  aks:        { cluster_role: view }   # CYNATIVE_CONNECTORS_AKS_CLUSTER_ROLE
  kubernetes: { cluster_role: view }   # CYNATIVE_CONNECTORS_KUBERNETES_CLUSTER_ROLE
```

> **Widening the role widens what Cynative can do.** The default `view` keeps
> Cynative read-only. Pointing a connector at a write-capable role (`edit`,
> `admin`, `cluster-admin`, or a custom role granting write verbs) makes the
> authorization gate permit exactly that role's verbs — including writes. The
> configured identity must also be able to **read** the chosen ClusterRole
> (`get clusterroles/<name>`).

## Limitations

- The gate trusts the fetched role. Cynative enforces *exactly* the
  rules of the configured ClusterRole (default `view`) and adds no independent
  mutation-verb floor. Kubernetes' built-in `view` is an **aggregated** role
  (`rbac.authorization.k8s.io/aggregate-to-view`), so if an administrator (or an
  installed controller) has aggregated write rules into `view`, Cynative would
  honor them. For least privilege, point the connector at a dedicated,
  non-aggregated read-only ClusterRole via `connectors.<eks|gke|aks|kubernetes>.cluster_role`.

- Kubernetes authorization here is client-side and complements cluster RBAC; it does not replace it. Keep the upstream identity's cluster permissions least-privilege.
- The enforced policy is the cluster's live configured ClusterRole (default `view`). If that role cannot be fetched or parsed, Cynative fails closed. The configured identity must itself be allowed to read that ClusterRole (`get clusterroles/<name>`), which the built-in `view` role does not itself grant — so an identity bound only to `view` cannot read its own policy source. This is most relevant to self-managed clusters where operators hand-craft minimal identities.
- Cynative's Kubernetes gate enforces exactly what the configured ClusterRole grants — it neither adds to nor subtracts from that role. The default upstream `view` role intentionally does **not** grant reading Secrets — per the [Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), reading Secret contents "enables access to ServiceAccount credentials in the namespace, which would allow API access as any ServiceAccount in the namespace (a form of privilege escalation)" — and grants no write verbs; it does, however, permit a broad set of reads (most namespaced resources, plus some cluster-scoped reads such as listing namespaces). Selecting a wider role widens the enforced surface accordingly — see [Configuration](#configuration).
- There is no client-side credential downscoping for Kubernetes. Authentication and authorization are decoupled — a bearer token or client certificate only authenticates, while authorization is server-side RBAC ([Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)) — so the in-process ClusterRole gate, host pinning, and dial-time IP authorization are the only client-side controls available.
- Non-resource URL access is limited to a safe read-only GET/HEAD allow-set; other non-resource paths are denied.
- The managed Kubernetes connectors are for Kubernetes API calls. Use `aws`, `gcp`, or `azure` for cloud control-plane discovery first, before calling cluster endpoints.
