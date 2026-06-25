# Connector guides

Cynative connectors let the research agent make authenticated, read-oriented API calls to systems that are already available from the local environment. Connectors are discovered at runtime; Cynative does not create new cloud, Kubernetes, or GitHub permissions.

## Quick start

Run `cynative -p "..."` from a shell that already has the credentials you want Cynative to use. If a connector can retrieve credentials, it is registered and shown to the agent as an available `auth_provider` for `http_request`.

## Connector catalog

| Connector id | System | Credential prerequisite | Guide |
|--------------|--------|-----------------|-------|
| `github` | GitHub REST API | a `gh` token for `github.com` validates live (probe `GET /user` → `/rate_limit`) | [github.md](github.md) |
| `gitlab` | GitLab REST API (gitlab.com or self-managed) | a `GITLAB_TOKEN`/`glab` token validates live (`GET /api/v4/user`) | [gitlab.md](gitlab.md) |
| `aws` | AWS service APIs | the AWS SDK default chain resolves and validates credentials live | [aws.md](aws.md) |
| `eks` | EKS Kubernetes APIs | AWS credentials validate (registers alongside `aws`) | [eks.md](eks.md) |
| `gcp` | Google Cloud APIs | Application Default Credentials resolve and validate live | [gcp.md](gcp.md) |
| `gke` | GKE Kubernetes APIs | GCP ADC validate (registers alongside `gcp`) | [gke.md](gke.md) |
| `azure` | Azure Resource Manager APIs | the Azure credential chain mints a test ARM control-plane token | [azure.md](azure.md) |
| `aks` | AKS Kubernetes APIs | the Azure credential chain mints a test ARM token (registers alongside `azure`) | [aks.md](aks.md) |
| `kubernetes` | Self-managed Kubernetes APIs | a kubeconfig context loads **and** a dial-guarded fetch of the configured ClusterRole succeeds | [kubernetes-self-managed.md](kubernetes-self-managed.md) |

## Targets and environment at a glance

Each connector's **target** — the account, project, subscription, cluster, or host it acts against — is decided by one of three mechanisms, and often a different one per facet (identity vs region vs cluster vs cloud):

- **Vendor credential discovery** — the vendor SDK/CLI cynative delegates to (the AWS SDK default chain, Google ADC, the Azure credential chain, `go-gh`, `glab`, kubeconfig). This is what honors vendor environment variables and config files.
- **Per-request argument** — a value the model supplies on each `http_request` (for example `aws_auth.region`, the project/subscription in the request URL, or the `eks_auth`/`gke_auth`/`aks_auth` cluster facts).
- **cynative config** — operator settings under `connectors.*` (for example `connectors.gitlab.host`, `connectors.azure.cloud`, and all the exposure controls in [Shared configuration](#shared-configuration)).

**cynative itself reads almost no vendor environment variables directly — the vendor SDK/CLI does.** To change the identity or target, set the vendor's own variables (or run its login command) in the shell cynative runs from; cynative's `CYNATIVE_*` variables control exposure and a few connector-specific settings, not vendor credentials.

| Connector | Default target | Set by | Change target via | Credential / identity source |
|---|---|---|---|---|
| `github` | `api.github.com` (fixed; GitHub Enterprise Server unsupported) | hardcoded in cynative | host not changeable; change identity via `gh auth login` / `GH_TOKEN` | `gh` CLI token (go-gh) |
| `gitlab` | `gitlab.com` (`/api/v4`) | cynative config `connectors.gitlab.host` | `connectors.gitlab.host` / `api_host` (or `CYNATIVE_CONNECTORS_GITLAB_*`) | `GITLAB_TOKEN` / `glab` config |
| `aws` | account/identity from the AWS SDK chain; region per request | vendor AWS SDK default chain | `AWS_PROFILE` / `AWS_REGION` / `~/.aws` | AWS SDK default credential chain |
| `eks` | none — cluster named per request | per-request `eks_auth` | `eks_auth.cluster_name` / `region`; identity via the AWS chain | AWS chain (STS-presigned Kubernetes token) |
| `gcp` | identity from ADC; project per request | vendor Google ADC chain | `gcloud auth application-default login` / `GOOGLE_APPLICATION_CREDENTIALS` | Google Application Default Credentials |
| `gke` | none — cluster named per request | per-request `gke_auth` | `gke_auth` project/location/cluster; identity via ADC | Google ADC |
| `azure` | identity from the Azure chain; subscription per request; cloud auto-detected | vendor azidentity chain (+ `connectors.azure.cloud`) | `az login` / `AZURE_*`; cloud via `connectors.azure.cloud` | Azure credential chain |
| `aks` | none — cluster named per request | per-request `aks_auth` | `aks_auth` subscription/resource-group/cluster; identity via the Azure chain | Azure chain (ARM `ListClusterUserCredentials`) |
| `kubernetes` | the kubeconfig current-context cluster | vendor kubeconfig discovery | `kubectl config use-context` / `KUBECONFIG` | kubeconfig (static token / client cert) |

Each connector page distributes the details across three sections: **Credential discovery** (identity sources + vendor credential variables), **Target selection** (what it points at, how to change it, and the per-request/targeting variables), and **Cynative configuration** (cynative's own exposure and cache knobs). See those sections for the relevant environment variables (vendor + cynative) and links to the official vendor documentation.

## Defense at a glance

| Control | AWS | GCP | Azure | GitHub | GitLab | EKS | GKE | AKS | K8s self-managed |
|---|---|---|---|---|---|---|---|---|---|
| Read-only by default | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Enforcement model | IAM action simulation | role permission eval | RBAC role-definition | read/write classifier | read/write classifier | live `view` RBAC | live `view` RBAC | live `view` RBAC | live `view` RBAC |
| Configurable exposure | ✓ any policy ARN | ✓ predefined roles | ✓ role name/GUID | ✓ (`connectors.github.permissions`: category[/subcategory] → read\|write\|none ceiling) | ✓ (`connectors.gitlab.permissions`: category → read\|write\|none ceiling; default read-only, `ci-variables` blocked) | ✓ (`cluster_role`) | ✓ (`cluster_role`) | ✓ (`cluster_role`) | ✓ (`cluster_role`) |
| Credential downscoping | ✓ STS-scoped, AWS-side — assumed-role identities only | — · CAB is GCS-only | — · no Entra primitive | — · user tokens | — · token scopes fixed at issue | — · authn/authz decoupled | — · authn/authz decoupled | — · authn/authz decoupled | — · authn/authz decoupled |
| Host pinning | ✓ | ✓ | ✓ (cloud) | ✓ | ✓ (+ port) | ✓ (endpoint) | ✓ (endpoint) | ✓ (endpoint) | ✓ (kubeconfig) |
| Dial-time IP authorization | ✓ internal-range deny | ✓ internal-range deny | ✓ internal-range deny | ✓ internal-range deny | ✓ internal-range deny (`allow_private_network` opt-in) | ✓ IP pin | ✓ IP pin (IP-literal only) | ✓ IP pin | ✓ IP pin (RFC1918 ok) |
| Model-supplied-credential rejection | ✓ | ✓ | ✓ (+SAS) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Response redaction | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Cynative ships a vendor-curated, read-only baseline that you can re-point to a different policy or role per connector — a spectrum of exposure that is safe by default, not a binary read/write toggle. **Only AWS has credential downscoping**, and even there it applies to **assumed-role identities only** (an STS `AssumeRole`-scoped session); IAM-user and root identities run unscoped with their base credentials, gated client-side by host pinning and the action gate. For every other connector the action/RBAC gate is the **sole client-side control**; the per-connector "Credential downscoping —" cells above link the reason, whether a vendor platform gap or a tracking issue. Kubernetes exposure is operator-selectable per connector via `connectors.<id>.cluster_role` (default the built-in `view` role). See each connector's page for its full "Defense at a glance" snapshot and limitations.

## Shared request model

All connector-backed requests go through the `http_request` tool. The model must set `auth_provider` to one of the registered connector ids and include the connector-specific auth argument object, such as `aws_auth`, `gcp_auth`, or `aks_auth`.

Cynative applies request authorization before attaching credentials, then applies the dial guard when the HTTP transport connects:

1. The URL must use HTTPS.
2. The selected connector must authorize the request host.
3. The selected connector must authorize the requested action when it implements action authorization.
4. Credentials are attached only after host and action authorization pass.
5. At dial time, the selected connector or the default dial guard authorizes the resolved IP address before the credential-bearing request is sent.

## Shared configuration

Connector hardening is configured under the top-level `connectors:` key in `~/.cynative/config.yaml`:

```yaml
cache:
  dir: ~/.cynative/cache
  ttl: 24h

connectors:
  github:
    permissions:        # category[/subcategory] → read|write|none; omit for the secure default
      default: read
  gitlab:
    permissions:        # category → read|write|none; omit for the secure default
      default: read
  aws:
    policy: arn:aws:iam::aws:policy/SecurityAudit
  gcp:
    role: roles/viewer
  azure:
    role_definition: Reader
```

Most keys are also settable through `CYNATIVE_*` environment variables, for example `CYNATIVE_CONNECTORS_AWS_POLICY`, `CYNATIVE_CONNECTORS_GCP_ROLE`, `CYNATIVE_CONNECTORS_AZURE_ROLE_DEFINITION`, `CYNATIVE_CACHE_DIR`, and `CYNATIVE_CACHE_TTL`. The GitHub and GitLab `permissions` maps take a compact comma-separated `key=value` form, e.g. `CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS="default=read,issues=write"` (a non-empty env value replaces the file map wholesale; a blank value is treated as unset).

## Managed Kubernetes connectors

EKS, GKE, and AKS share the Kubernetes API hardening model described in [kubernetes.md](kubernetes.md). Their individual pages document how each managed service resolves cluster credentials, endpoint hosts, CA data, and connector-specific limitations.

## Least privilege

Cynative's connector hardening is a client-side safety layer. Use least-privilege upstream credentials whenever possible. Cynative can restrict, reject, or fail closed in many cases, but it does not replace IAM, RBAC, Azure RBAC, or GitHub token scoping.
