# GCP connector

**Connector id:** `gcp`
**Scope:** Google Cloud APIs using Application Default Credentials.

### Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | per-operation IAM permission check against the configured role |
| Configurable exposure | ✓ any predefined role (`roles/…`, default `roles/viewer`) or custom role (`projects/<p>/roles/<r>`, `organizations/<o>/roles/<r>`) |
| Credential downscoping | — · no general primitive (GCP Credential Access Boundaries are Cloud-Storage-only) |
| Host pinning | ✓ (Discovery-directory catalog: host→service/location) |
| Dial-time IP authorization | ✓ (default internal-range deny) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Quick start

Run Cynative from an environment where ADC works:

```bash
gcloud auth application-default login
cynative -p "find externally exposed GCP load balancers"
```

## Credential discovery

Cynative calls Google Application Default Credentials with the `https://www.googleapis.com/auth/cloud-platform` scope.

### Credential sources

Cynative loads GCP credentials through `google.FindDefaultCredentials`. The ADC search order determines which identity is used — cynative reads `GOOGLE_APPLICATION_CREDENTIALS` (and, on Windows, `APPDATA` to locate the well-known ADC file) only as startup presence signals. The gcloud project/config variables (`CLOUDSDK_*`, `GOOGLE_CLOUD_PROJECT`) are **not** consulted by cynative's project resolution — see [Target selection](#target-selection) for what actually sets the permission-catalog project.

- `GOOGLE_APPLICATION_CREDENTIALS` — path to a credential JSON; first source in the ADC search order.

### Registration and validation

Cynative finds ADC and then **eagerly validates it at startup** by minting a test cloud-platform token; the `gcp` and `gke` connectors register only if that succeeds. If ADC cannot be found, or the credential cannot mint a token (for example a revoked refresh token), both connectors are skipped. That skip is shown (as unavailable at startup) only when GCP is explicitly configured — `GOOGLE_APPLICATION_CREDENTIALS` set or a well-known ADC file present — or under `--verbose`; an ambient no-ADC workstation is skipped quietly.

### References

- [How Application Default Credentials works](https://docs.cloud.google.com/docs/authentication/application-default-credentials) — the ADC search order that determines identity (`GOOGLE_APPLICATION_CREDENTIALS` → the `gcloud auth application-default login` file → the metadata server).

## Target selection

### Default target

The identity is whatever the ADC chain resolves — typically the user credentials written by `gcloud auth application-default login`, or an attached service account on a GCP host. There is no single fixed project target: the specific project/resource is chosen per request by the model in the request URL path (for example `.../v1/projects/{project}/...`). The ADC-probed project is consulted only to build the testable-permission catalog the action gate uses, not to scope which project a request hits.

### Change the target

Change the identity by re-pointing ADC: run `gcloud auth application-default login`, set `GOOGLE_APPLICATION_CREDENTIALS` to a credential JSON (see [Credential discovery](#credential-discovery)), or run on a host with a different attached service account.

Change the project cynative reports for the permission catalog at its source. cynative resolves that project from the ADC credential, in order: the credential's own project (`Credentials.ProjectID` — populated from a service-account key's `project_id`; empty for `gcloud auth application-default login` user credentials), then the ADC file's `quota_project_id`, then the GCE metadata project. So set one of:

- point `GOOGLE_APPLICATION_CREDENTIALS` at a service-account key whose `project_id` is the target;
- set the ADC quota project — `gcloud auth application-default set-quota-project PROJECT` (writes `quota_project_id` into the ADC file), used when the credential carries no project;
- run on a GCE/Cloud Run host whose attached metadata project is the target.

Note: `GOOGLE_CLOUD_PROJECT` and the gcloud active-config variables (`CLOUDSDK_CORE_PROJECT`, `CLOUDSDK_CONFIG`, `CLOUDSDK_ACTIVE_CONFIG_NAME`) are **not** consulted by cynative's ADC project resolution — the pinned `golang.org/x/oauth2/google` chain does not read them into `Credentials.ProjectID` — so they do not retarget the permission-catalog project.

To target a project on a given call, the model puts that project id in the request URL. `connectors.gcp.role` sets the action-gate exposure ceiling, not the target — see [Cynative configuration](#cynative-configuration).

### Targeting inputs

The service and location for each call come from the per-request `gcp_auth` object — `gcp_auth.service` (required) and `gcp_auth.location` (optional; used for regional or locational endpoints, omitted for global endpoints); see [Request usage](#request-usage) for the full schema.

- [Managing gcloud CLI configurations](https://docs.cloud.google.com/sdk/docs/configurations) — `gcloud config set project`, `CLOUDSDK_CORE_PROJECT`, `CLOUDSDK_CONFIG`, `CLOUDSDK_ACTIVE_CONFIG_NAME`.

## Request usage

### Required `http_request` args

Use `auth_provider: "gcp"` and include:

```json
{
  "gcp_auth": {
    "service": "compute",
    "location": "us-central1"
  }
}
```

`gcp_auth.service` is required. `gcp_auth.location` is used for regional or locational endpoints and is omitted for global endpoints.

### Minimal example

```js
const project = "my-project";
const resp = await http_request({
  method: "GET",
  url: `https://cloudresourcemanager.googleapis.com/v1/projects/${project}`,
  headers: [],
  body: "",
  auth_provider: "gcp",
  gcp_auth: { service: "cloudresourcemanager" }
});
console.log(resp.body);
```

## Hardening

Cynative's GCP connector is built for read-oriented cloud research with client-side checks around every model-authored request. Because GCP has no general credential-downscoping primitive, the in-process action gate is the client-side control: a request resolves to a service and operation, those resolve to required IAM permissions, and every permission must be granted by the configured role before the ADC token is attached.

Two baseline protections apply before any request is sent:

- Requests with model-supplied credentials in an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fail closed.
- Credentials are injected as an ADC bearer token only after the host-pinning and action-authorization gates pass.

In request order:

- **Host pinning.** Cynative resolves Google API hosts to a service and location through the cached Discovery directory catalog. The resolved service and location must match the model-supplied `gcp_auth` claim, so a request cannot claim one Google service while sending credentials to another.
- **Action authorization.** Cynative classifies the API operation, resolves the IAM permissions it requires, and authorizes every required permission against the configured role. The gate fails closed: if Cynative cannot resolve the service, operation, or required permissions, the request is denied.
- **Permissionless reads.** A small fixed set of methods need no IAM permission and are allowed without a role check: `oauth2.tokeninfo`, `discovery.apis.getRest`, `discovery.apis.list`, and any `*.testIamPermissions` probe. These are pinned by an explicit allow-list rather than matched by prefix.
- **Response redaction.** Secret-shaped content and credential-named fields are redacted from responses before the model sees them. Redaction is a defense-in-depth layer, not a reason to treat returned GCP data as public — see the limitations below.

The default role is `roles/viewer`. The configured role is shown in the startup connector inventory as `role=roles/viewer` (or the custom role you configure), so operators can confirm the gate is active at a glance. The model also receives the effective role in its system prompt.

### Choosing your exposure level

Cynative ships a curated read-only baseline — the `roles/viewer` predefined role — and lets you re-point the action gate at a different role with `connectors.gcp.role`. Exposure is a spectrum, not a binary toggle: you can widen or narrow the agent's reach by choosing a broader or tighter role, and every model-authored request is checked against whichever role you configure.

The configured role may be a **predefined** role (`roles/<id>`) or a **custom** role
(`projects/<p>/roles/<r>` or `organizations/<o>/roles/<r>`). The role is an
**operator-chosen ceiling, not inherently read-only**: a custom role granting write
permissions widens the gate accordingly — Cynative ships `roles/viewer` as the
read-only default, and a custom role's read-only-ness is the operator's
responsibility. Resolving a custom role requires the ADC principal to hold
`iam.roles.get` on the role's project or organization; if the role cannot be
fetched, or is **disabled / soft-deleted**, the gate fails closed and denies every
request with a `gcp_hardening: not_ready: …` error returned to the model (the
wrapped cause names the role-fetch failure or the disabled role).

### How this compares to read-only alternatives

As of June 2026, no official Google MCP server ships a read-only, least-privilege control-plane connector for broad GCP resources:

- [`gcloud-mcp`](https://github.com/googleapis/gcloud-mcp) enforces only a client-side command denylist.
- The [MCP Toolbox](https://github.com/googleapis/mcp-toolbox) is database-scoped, not a broad control-plane connector.
- The [Cloud Run MCP server](https://github.com/GoogleCloudPlatform/cloud-run-mcp) is write-oriented (it deploys services).

Google's documented read-only mechanism for its MCP tooling is [server-side IAM deny policies on a tool annotation](https://docs.cloud.google.com/mcp/prevent-read-write-tool-use), not an in-server flag.

Cynative's posture is different: it gates every model-authored operation with a per-operation IAM-permission check against a curated read-only predefined role, so the read decision is made against your configured GCP permissions rather than left to a client-side allow/denylist.

> Third-party behavior was checked against official docs in June 2026; these tools change quickly, so re-verify before relying on this.

## Cynative configuration

### Exposure & authorization settings

The predefined or custom role the action gate authorizes against. Default `roles/viewer`; see [Hardening](#hardening) for how it is applied.

```yaml
connectors:
  gcp:
    role: roles/viewer
```

```bash
export CYNATIVE_CONNECTORS_GCP_ROLE=roles/viewer
```

A custom role is configured the same way:

```yaml
connectors:
  gcp:
    role: projects/my-project/roles/cynativeReadonly
```

```bash
export CYNATIVE_CONNECTORS_GCP_ROLE=projects/my-project/roles/cynativeReadonly
```

### Cache settings

GCP hardening metadata (Discovery catalog and iam-dataset permission registry) is cached under `<cache.dir>/gcp` and refreshed after `cache.ttl`. The role definition is fetched live per run and is not cached. The cache is shared across connectors — see [Shared configuration](README.md#shared-configuration).

```yaml
cache:
  dir: ~/.cynative/cache
  ttl: 24h
```

```bash
export CYNATIVE_CACHE_DIR=~/.cynative/cache
export CYNATIVE_CACHE_TTL=24h
```

## Limitations

- Credential downscoping is not used. GCP [Credential Access Boundaries](https://cloud.google.com/iam/docs/downscoping-short-lived-credentials) are Cloud-Storage-only, so there is no general downscoping primitive to re-vend a narrower ambient credential; the in-process action gate is therefore the sole client-side control.
- Custom roles are resolved per run via `iam.roles.get`, which the ADC principal must be granted on the role's project or organization; an unresolvable, disabled, or soft-deleted role fails closed (all requests denied). The role's required permissions are still evaluated against the **caller's project** testable-permission catalog, so organization-level operations whose permissions are not testable at the caller project may be denied regardless of the configured role. Common Resource Manager resource-discovery methods (`projects`/`folders`/`organizations` list and search) are an exception: their required permission is supplied by a pinned override, so they resolve correctly despite being parent-scoped and are then evaluated against the configured role like any other operation.
- Action authorization fails closed when service, operation, or permission resolution fails.
- The GCP connector is for Google Cloud APIs. Use `gke` for Kubernetes API calls to GKE clusters.
