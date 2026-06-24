# AKS connector

**Connector id:** `aks`
**Scope:** Kubernetes API requests to Azure Kubernetes Service clusters.

## Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | the cluster's live configured ClusterRole (default `view`; allow-only RBAC), via kube-apiserver-style request classification — see [kubernetes.md](kubernetes.md) |
| Configurable exposure | ✓ · `connectors.aks.cluster_role` selects the authorization ClusterRole (default `view`); see [kubernetes.md](kubernetes.md#configuration) |
| Credential downscoping | — · Kubernetes decouples authn from authz; no client-side downscoping primitive |
| Host pinning | ✓ (kubeconfig cluster `server` from ARM `ListClusterUserCredentials`) |
| Dial-time IP authorization | ✓ (dialed IP must be in the resolved endpoint IP set) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Quick start

Run Cynative from an environment with a configured Azure CLI, environment, workload identity, or another source in Cynative's Azure credential chain. Discover the cluster endpoint through the [Azure connector](azure.md) first, then use the AKS connector for Kubernetes API requests.

## Credential discovery

### Credential sources

The AKS connector uses the shared Azure credential chain (the [azure connector](azure.md)'s, with managed identity demoted to last); all of the azure connector's identity variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH` with optional `AZURE_CLIENT_CERTIFICATE_PASSWORD`, `AZURE_USERNAME`, `AZURE_PASSWORD`, `AZURE_FEDERATED_TOKEN_FILE`) apply — see the [azure connector](azure.md#credential-discovery). Per request it lazily calls ARM `ListClusterUserCredentials` for the target cluster and parses the returned kubeconfig: a bearer token is used if present, client certificate and key data are supplied to the TLS transport if present, otherwise Cynative falls back to a Microsoft Entra ID token for the fixed AKS API server audience.

### Registration and validation

The AKS connector registers alongside the `azure` connector and is gated on the same eager Azure ARM-token probe at startup (see the [azure connector](azure.md#credential-discovery)) — if that probe fails, both `azure` and `aks` show unavailable. The per-cluster ARM `ListClusterUserCredentials` kubeconfig retrieval then happens lazily at request time and can still fail there.

### References

- [Authenticate Go apps to Azure](https://learn.microsoft.com/en-us/azure/developer/go/sdk/authentication/authentication-overview) — the azidentity credential model (identity sources).
- [azidentity package reference](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity) — the EnvironmentCredential variable spellings and the credential source set.

## Target selection

### Default target

None — the AKS connector has no default cluster. It uses the shared Azure credential chain against the resolved Azure cloud (public by default); the target managed cluster is named per request via `aks_auth.subscription_id` / `resource_group` / `cluster_name`, and its endpoint and TLS material are resolved at request time via ARM (see [Credential discovery](#credential-discovery)).

### Change the target

Change the cluster by passing different `aks_auth.subscription_id` / `resource_group` / `cluster_name` per request (the endpoint is verified against ARM, never guessed). Change the identity by re-pointing the Azure credential chain — `az login` (optionally `az account set --subscription <id>`) or the environment service-principal variables (see [Credential discovery](#credential-discovery)); the identity needs the **Azure Kubernetes Service Cluster User Role** (`Microsoft.ContainerService/managedClusters/listClusterUserCredential/action`). The Azure cloud is the shared `connectors.azure.cloud` setting — configure it on the [azure connector](azure.md#cynative-configuration). Change the authorization ceiling with `connectors.aks.cluster_role` (see [Cynative configuration](#cynative-configuration)).

### Targeting inputs

The target cluster comes from the per-request `aks_auth` object — `aks_auth.subscription_id`, `aks_auth.resource_group`, and `aks_auth.cluster_name` (all required); see [Request usage](#request-usage) for the full schema. The vendor `AZURE_AUTHORITY_HOST` / `AZURE_CONFIG_DIR` variables feed the shared cloud auto-detect under `cloud: auto`.

- [Limit access to cluster configuration in AKS](https://learn.microsoft.com/en-us/azure/aks/control-kubeconfig-access) — `az aks get-credentials --resource-group <rg> --name <cluster>` and the "Cluster User Role" / `listClusterUserCredential` action cynative invokes.

## Request usage

### Required `http_request` args

Use `auth_provider: "aks"` and include:

```json
{
  "aks_auth": {
    "subscription_id": "00000000-0000-0000-0000-000000000000",
    "resource_group": "rg-prod",
    "cluster_name": "prod"
  }
}
```

`aks_auth.subscription_id`, `aks_auth.resource_group`, and `aks_auth.cluster_name` are required for hardening and TLS resolution.

### Minimal example

```js
const resp = await http_request({
  method: "GET",
  url: "https://prod-dns-00000000.hcp.eastus.azmk8s.io/api",
  headers: [],
  body: "",
  auth_provider: "aks",
  aks_auth: {
    subscription_id: "00000000-0000-0000-0000-000000000000",
    resource_group: "rg-prod",
    cluster_name: "prod"
  }
});
console.log(resp.body);
```

## Hardening

Cynative's AKS connector is built for read-oriented Kubernetes research. AKS first resolves the cluster's kubeconfig through ARM, then applies the same per-request controls in request order before any model-authored call reaches the cluster:

- **Host pinning.** The request host must match the kubeconfig cluster `server` host returned by ARM `ListClusterUserCredentials`. A request whose host is not the pinned endpoint is rejected, so a model cannot steer the credential to a different target.
- **Kubernetes action authorization.** Each request is classified the way the kube-apiserver does and authorized against the cluster's own live `view` ClusterRole before any credential is attached — the shared, allow-only RBAC model documented in [kubernetes.md](kubernetes.md), which also fails closed when `view` cannot be resolved.
- **Credential injection.** Only after host and action authorization pass does Cynative attach a credential: a kubeconfig bearer token, client certificate data supplied to the TLS transport, or a Microsoft Entra ID token for the AKS API server audience. Model-supplied credentials are rejected before injection — requests carrying an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fail closed.
- **Dial-time IP authorization.** The transport's dial guard authorizes the DNS-resolved IP before connecting, on every dial: the dialed IP must be in the resolved cluster-endpoint IP set and must pass the shared forbidden-address floor, closing DNS-rebinding and TOCTOU windows.

Responses are redacted for secret-shaped content and credential-named fields before they return to the model. For the full shared authorization model, the host/address controls, and how this compares to read-only Kubernetes MCP servers, see [kubernetes.md](kubernetes.md). The cluster is discovered through the [Azure connector](azure.md) before any AKS call is made.

## Cynative configuration

### Exposure & authorization settings

The read-only ClusterRole this connector authorizes against is configurable
(default `view`); see the [shared Kubernetes model](kubernetes.md#configuration)
for the widening warning. The Azure cloud is the shared `connectors.azure.cloud` setting — configure it on the [azure connector](azure.md#cynative-configuration).

```yaml
connectors:
  aks:
    cluster_role: view   # env CYNATIVE_CONNECTORS_AKS_CLUSTER_ROLE
```

## Limitations

- The connector depends on Azure credentials that can call [`ListClusterUserCredentials`](https://learn.microsoft.com/en-us/rest/api/aks/managed-clusters/list-cluster-user-credentials) for the cluster, which returns a base64-encoded kubeconfig.
- The credential cascade is **local bearer token → local client certificate (mTLS) → fallback Microsoft Entra ID token**, and it applies only when that ARM call succeeds. When the returned kubeconfig carries no static bearer or certificate (for example a cluster with [`disableLocalAccounts`](https://learn.microsoft.com/en-us/azure/aks/local-accounts)), Cynative uses the Entra ID token; if the ARM credential call itself fails, the request fails closed. See also AKS [cluster authentication concepts](https://learn.microsoft.com/en-us/azure/aks/concepts-cluster-authentication).
- With [AKS-managed Microsoft Entra integration](https://learn.microsoft.com/en-us/azure/aks/kubernetes-rbac-entra-id), Entra authenticates the caller while Kubernetes RBAC authorizes the request.
- The model must first discover or verify the cluster endpoint. The connector verifies the endpoint but does not guess the URL.
- There is no client-side credential downscoping. Kubernetes decouples authentication from authorization ([Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)), so the in-process `view` gate, host pinning, and dial-time IP authorization are the only client-side controls.
