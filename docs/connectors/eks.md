# EKS connector

**Connector id:** `eks`
**Scope:** Kubernetes API requests to Amazon EKS clusters.

EKS builds on AWS credentials: discover the cluster endpoint through the [AWS connector](aws.md) first, then use the EKS connector for Kubernetes API requests. Kubernetes API authorization, host pinning, dial-time IP authorization, and response redaction follow the shared [Kubernetes connector hardening](kubernetes.md) model.

### Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | the cluster's live configured ClusterRole (default `view`; allow-only RBAC), via kube-apiserver-style request classification — see [kubernetes.md](kubernetes.md) |
| Configurable exposure | ✓ · `connectors.eks.cluster_role` selects the authorization ClusterRole (default `view`); see [kubernetes.md](kubernetes.md#configuration) |
| Credential downscoping | — · Kubernetes decouples authn from authz; no client-side downscoping primitive |
| Host pinning | ✓ (cluster endpoint from `DescribeCluster`) |
| Dial-time IP authorization | ✓ (dialed IP must be in the resolved endpoint IP set) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Quick start

Run Cynative from an environment where AWS credentials are available. Discover the cluster endpoint through the AWS connector, then use the EKS connector for Kubernetes API requests.

## Credential discovery

### Credential sources

The EKS connector inherits AWS credentials via the AWS SDK default credential chain. Cynative uses those AWS credentials to presign an STS `GetCallerIdentity` request and builds the Kubernetes bearer token expected by the EKS authenticator. The AWS SDK chain reads these variables — cynative does not read them to authenticate; it inspects the credential/profile/role/file ones only as a startup presence signal for skip-logging:

- `AWS_PROFILE` — selects the named shared-config/credentials profile (also implies the target account; see [Target selection](#target-selection)).
- `AWS_DEFAULT_PROFILE` — legacy profile selector, lower precedence than `AWS_PROFILE`.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` — static or temporary credentials for the inherited identity.
- `AWS_ROLE_ARN` / `AWS_WEB_IDENTITY_TOKEN_FILE` — web-identity role to assume — changes which identity (and reachable clusters) cynative inherits.
- `AWS_CONFIG_FILE` / `AWS_SHARED_CREDENTIALS_FILE` — override the AWS config/credentials file paths.
- `AWS_CA_BUNDLE` — TLS CA bundle for HTTPS validation (transport trust only — not a credential or a target).

See the [AWS connector](aws.md) for the full chain and variable set.

### Registration and validation

The EKS connector registers together with the `aws` connector, gated on the same eager AWS validation at startup — config load, credential retrieval, and an `sts:GetCallerIdentity` liveness check (see the [aws connector](aws.md#credential-discovery)). If any of those fail, both `aws` and `eks` are not registered. The EKS-specific cluster endpoint, CA, and bearer token are resolved later, per request (not at registration).

### References

- [AWS CLI environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html) — the identity variables the inherited AWS chain consults.
- [Create an EKS kubeconfig file](https://docs.aws.amazon.com/eks/latest/userguide/create-kubeconfig.html) — `aws eks update-kubeconfig --region <region> --name <cluster>` and the `eks:DescribeCluster` permission (the same API cynative calls); note cynative does not consume kubeconfig for EKS.

## Target selection

### Default target

None — the EKS connector has no default cluster. Each request names a specific Amazon EKS cluster via `eks_auth.cluster_name` (with optional `eks_auth.region`); cynative inherits the AWS account/identity and the fallback region from the AWS SDK default credential chain (see the [AWS connector](aws.md)). At request time cynative resolves the cluster's endpoint host and CA via the EKS `DescribeCluster` API (the bearer token is minted as described above). Region resolves as `eks_auth.region` → SDK-configured region → `us-east-1`.

### Change the target

To target a different cluster, change the per-request `eks_auth.cluster_name` / `region` — there is no default-cluster setting. To change which AWS account/identity (and thus which clusters are reachable) and the fallback region, use the standard AWS SDK/CLI mechanisms the [AWS connector](aws.md) documents (`AWS_PROFILE`, credentials files, `AWS_REGION`); these variables are documented under [Credential discovery](#credential-discovery). cynative does not read kubeconfig for EKS; the standard `aws eks update-kubeconfig` flow is only a way to discover/verify a cluster. To adjust the read-only authorization ceiling (not the target), set `connectors.eks.cluster_role` (see [Cynative configuration](#cynative-configuration)).

The fallback region when `eks_auth.region` is omitted resolves from `AWS_REGION` (which overrides `AWS_DEFAULT_REGION`), then defaults to `us-east-1`.

### Targeting inputs

Each Kubernetes API call to an EKS cluster requires `eks_auth.cluster_name` and optionally `eks_auth.region`. See [Request usage](#request-usage) for the full schema and a minimal example.

- [Amazon EKS clusters](https://docs.aws.amazon.com/eks/latest/userguide/clusters.html) — cluster naming and regional availability.

## Request usage

### Required `http_request` args

Use `auth_provider: "eks"` and include:

```json
{
  "eks_auth": {
    "cluster_name": "prod",
    "region": "us-east-1"
  }
}
```

`eks_auth.cluster_name` is required. `eks_auth.region` defaults to the SDK-configured AWS region, then `us-east-1` if neither is set.

### Minimal example

```js
const resp = await http_request({
  method: "GET",
  url: "https://EXAMPLE.gr7.us-east-1.eks.amazonaws.com/api",
  headers: [],
  body: "",
  auth_provider: "eks",
  eks_auth: { cluster_name: "prod", region: "us-east-1" }
});
console.log(resp.body);
```

## Hardening

The EKS connector is built for read-oriented Kubernetes API research. Cynative resolves the cluster endpoint and CA data through the AWS EKS `DescribeCluster` API, then runs every model-authored request through the shared Kubernetes controls in request order before any credential is attached and the connection is dialed:

- **Host pinning.** The request host must match the resolved cluster endpoint host. A request whose host is not the pinned endpoint is rejected.
- **Kubernetes action authorization.** Each request is classified the way the kube-apiserver classifies it and authorized against the cluster's own live read-only `view` ClusterRole, failing closed when that policy cannot be resolved. This is the shared model — see the [Kubernetes connector hardening](kubernetes.md) for the full RBAC model and the read-only MCP comparison.
- **Credential injection.** Model-supplied credentials are rejected before injection: a request carrying an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fails closed. Only after host and Kubernetes action authorization pass does Cynative attach the EKS Kubernetes bearer token.
- **Dial-time IP authorization.** The transport's dial guard authorizes the DNS-resolved IP before connecting, on every dial: the dialed IP must be in the resolved cluster endpoint IP set and must pass the shared forbidden-address floor.

## Cross-links

- [kubernetes.md](kubernetes.md) — the shared Kubernetes API hardening model (request classification, `view` RBAC authorization, dial controls) and the comparison to read-only Kubernetes MCP servers.
- [aws.md](aws.md) — AWS control-plane discovery. EKS depends on AWS credentials; discover and verify the cluster endpoint through the AWS connector first.

## Cynative configuration

### Exposure & authorization settings

The read-only ClusterRole this connector authorizes against is configurable (default `view`); see the [shared Kubernetes model](kubernetes.md#configuration) for the widening warning.

```yaml
connectors:
  eks:
    cluster_role: view
```

```bash
export CYNATIVE_CONNECTORS_EKS_CLUSTER_ROLE=view
```

## Limitations

- The connector depends on AWS credentials that can call the needed EKS and STS APIs. Without `eks:DescribeCluster` access the endpoint and CA data cannot be resolved.
- The model must first discover or know the cluster endpoint. The connector verifies the endpoint but does not guess the URL.
- EKS bearer-token generation uses the local AWS credentials' permissions and is **not** downscoped. Kubernetes decouples authentication from authorization, so there is no client-side credential downscoping — authorization is server-side cluster RBAC ([Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)). The in-process `view` gate, host pinning, and dial-time IP authorization are the client-side controls.
