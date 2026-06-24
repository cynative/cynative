# Azure connector

**Connector id:** `azure`
**Scope:** Azure Resource Manager control-plane APIs.

### Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | per-operation RBAC check against the configured role definition (control-plane only) |
| Configurable exposure | ✓ any built-in role name or role-definition GUID (default `Reader`) |
| Credential downscoping | — · no Entra ID RBAC-downscoping primitive (RBAC is evaluated server-side per request) |
| Host pinning | ✓ (pinned to the configured/resolved Azure cloud) |
| Dial-time IP authorization | ✓ (default internal-range deny) |
| Model-supplied-credential rejection | ✓ (+ rejects a SAS `sig=` query parameter) |
| Response redaction | ✓ |

## Quick start

Run Cynative from an environment with a configured Azure CLI, environment, workload identity, or another source in Cynative's Azure credential chain:

```bash
az login
cynative -p "review public Azure storage accounts"
```

## Credential discovery

### Credential sources

Cynative uses its Azure credential chain, based on DefaultAzureCredential sources. CLI, environment, workload identity, and other non-managed-identity sources are preferred; managed identity is tried last and is non-fatal so a metadata probe on a non-Azure host does not abort the chain. cynative reads no `AZURE_*` variable to authenticate — the azidentity chain does; the credential-shaped variables it reads directly serve only as startup presence signals (loud-vs-quiet skip):

- `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` — environment service-principal identity (secret auth).
- `AZURE_CLIENT_CERTIFICATE_PATH` (and `AZURE_CLIENT_CERTIFICATE_PASSWORD` for a password-protected certificate) — service-principal certificate auth.
- `AZURE_USERNAME` / `AZURE_PASSWORD` — username/password (ROPC) identity path.
- `AZURE_FEDERATED_TOKEN_FILE` — workload-identity federated token file.

(`AZURE_AUTHORITY_HOST` and `AZURE_CONFIG_DIR` are read to auto-detect the target cloud — see [Target selection](#target-selection).)

### Registration and validation

After constructing the chain, Cynative **eagerly validates it at startup** by minting a test ARM control-plane token; the `azure` and `aks` connectors register only if that probe succeeds (a transient error is retried once). A credential that cannot mint a token leaves the connector unavailable at startup. That skip is shown only when Azure is explicitly configured via the environment service-principal variables (`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / …) or under `--verbose`; an interactive-CLI-only failure — for example an expired or not-logged-in `az login` — is skipped **quietly**, because the Azure CLI, Developer CLI, and PowerShell credentials are not treated as explicit configuration. Per-request ARM calls can still fail afterward.

### References

- [Authenticate Go apps to Azure](https://learn.microsoft.com/en-us/azure/developer/go/sdk/authentication/authentication-overview) — the azidentity credential model cynative mirrors (identity sources).
- [EnvironmentCredential environment variables](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential) — the authoritative `AZURE_*` environment-variable spellings (the names are identical across azidentity SDKs).

## Target selection

### Default target

The identity is whatever the credential chain resolves (see [Credential discovery](#credential-discovery)). The target subscription/resource is not a default: it is named per request inside the ARM URL path (for example `/subscriptions/<id>/...`). The Azure cloud defaults to auto-detected public (`AzureCloud`) unless overridden.

### Change the target

Change the identity by re-pointing the credential chain: run `az login`, or set the environment service-principal variables (see [Credential discovery](#credential-discovery)). Target a subscription/resource per request by writing the subscription id into the ARM URL (there is no `AZURE_SUBSCRIPTION_ID` knob). Select the cloud with `connectors.azure.cloud` (or `CYNATIVE_CONNECTORS_AZURE_CLOUD`) = `AzureCloud` / `AzureUSGovernment` / `AzureChinaCloud`; under the default `auto`, the cloud follows the vendor `AZURE_AUTHORITY_HOST` and then the Azure CLI active cloud (`az cloud set --name ...`, stored in `$AZURE_CONFIG_DIR/config`). See [Cynative configuration](#cynative-configuration) for the cloud and role-definition settings, and [Sovereign clouds](#sovereign-clouds) for how the cloud is resolved. Note: `connectors.azure.cloud` sets the ARM endpoint/audience cynative targets and the cloud for the environment, workload-identity, and managed-identity credentials, but the Azure CLI, Developer CLI, and PowerShell credentials mint tokens against their **own** active cloud — on a sovereign cloud, also run `az cloud set --name ...` so the CLI credential matches, or it will issue tokens for the wrong cloud.

### Targeting inputs

The subscription/resource is the `/subscriptions/<id>/...` segment of the request URL; per request, `azure_auth.service` (required) selects the service, and `azure_auth.cloud` (optional) is a **claim verified** against the cloud cynative resolved at startup — it is derived from the host when omitted and **cannot switch clouds per request** (a mismatch is rejected). To target a different cloud, set `connectors.azure.cloud` before startup. See [Request usage](#request-usage). The vendor `AZURE_AUTHORITY_HOST` / `AZURE_CONFIG_DIR` variables are the cloud auto-detect signals under `cloud: auto`.

- [Manage Azure clouds with the Azure CLI](https://learn.microsoft.com/en-us/cli/azure/manage-clouds-azure-cli) — `az cloud list` / `show` / `set --name` to change the active cloud cynative auto-detects under `cloud: auto`.

## Request usage

### Required `http_request` args

Use `auth_provider: "azure"` and include:

```json
{
  "azure_auth": {
    "service": "Microsoft.Compute",
    "cloud": "AzureCloud"
  }
}
```

`azure_auth.service` is required. `azure_auth.cloud` is optional and defaults from the request host when omitted.

### Minimal example

```js
const subscription = "00000000-0000-0000-0000-000000000000";
const resp = await http_request({
  method: "GET",
  url: `https://management.azure.com/subscriptions/${subscription}?api-version=2020-01-01`,
  headers: [],
  body: "",
  auth_provider: "azure",
  azure_auth: { service: "Microsoft.Resources", cloud: "AzureCloud" }
});
console.log(resp.body);
```

## Hardening

Cynative's Azure connector is built for read-oriented cloud research with controls around every model-authored request. Azure has no credential-downscoping primitive, so this in-process action gate is the sole client-side control: each request is host-pinned, classified, and authorized against the configured RBAC role definition before an ARM token is injected, and the response is redacted before it returns to the model.

The default role definition is `Reader`, an Azure built-in role intended for control-plane reads. You can re-point it to a different built-in role or role-definition GUID with `connectors.azure.role_definition`.

The checks below run in request order, before any ARM token is attached:

- Cynative rejects any non-`https` URL, so credentials never traverse plaintext.
- Cynative rejects model-supplied credentials before injection (a gate shared by every connector): requests carrying an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fail closed. The Azure connector additionally rejects a SAS `sig=` query parameter.
- Cynative pins ARM requests to the configured or resolved Azure cloud, so a model-authored request cannot claim one Azure cloud while sending the token to another.
- Cynative resolves the request to a service via a cached catalog, classifies the requested ARM operation, and authorizes it against the configured Azure RBAC role definition. The gate fails closed: if the operation or the role definition cannot be resolved, the request is denied.
- Cynative injects an ARM bearer token only after these gates pass.

At connection time — after the token is attached but before any bytes go on the wire — a dial-time guard authorizes the DNS-resolved IP, denying internal ranges (loopback, link-local including cloud metadata, RFC1918, ULA) by default, which closes DNS-rebinding and TOCTOU windows. Finally, Cynative redacts secret-shaped content and credential-named fields from responses before the model sees them — treat returned Azure data as sensitive regardless.

Hardening metadata (the service catalog) is cached under the shared `cache.dir` and refreshed after `cache.ttl`; the role definition is fetched live per run. The configured role definition is shown in the startup connector inventory as `role definition=Reader` (or the role you configure), so operators can confirm the role in force. The model also receives the effective role definition in its system prompt.

### Choosing your exposure level

Cynative ships a curated read-only baseline — the Azure built-in `Reader` role — rather than a single on/off switch. Exposure is a spectrum: you can re-point `connectors.azure.role_definition` at any other built-in role name (for example a narrower service-specific reader) or at a role-definition GUID for a custom role, and the per-operation gate then authorizes against whatever role you name. A tighter role narrows what the agent may call; the default keeps the agent at control-plane read access.

### Sovereign clouds

Cynative supports the Azure public cloud and the sovereign clouds — Azure US Government (`management.usgovcloudapi.net`) and Azure China / 21Vianet (`management.chinacloudapi.cn`). The ARM endpoint, token audience, and Microsoft Entra ID authority are selected per cloud, so a token minted for one cloud is never sent to another.

By default (`connectors.azure.cloud: auto`) Cynative detects the cloud the same way `az cloud show` does: it reads the `AZURE_AUTHORITY_HOST` environment variable (if set) and then the Azure CLI config (`$AZURE_CONFIG_DIR/config`, default `~/.azure/config`, `[cloud] name`), falling back to the public cloud. Pin it explicitly with `connectors.azure.cloud` (`AzureCloud` | `AzureUSGovernment` | `AzureChinaCloud`) for environments where auto-detection is not reliable — for example managed identity on a sovereign host, where the cloud is not exposed without a network probe Cynative deliberately does not make. The `aks` connector inherits the same resolved cloud.

### How this compares to read-only alternatives

The official [Azure MCP Server](https://github.com/Azure/azure-mcp/blob/main/docs/azmcp-commands.md) ships a `--read-only` flag that filters the exposed tool list down to read-only tools — client-side tool gating in front of the credential. Cynative instead resolves each ARM operation and authorizes it against the configured RBAC role definition (control-plane only). The two sit at different points: a filtered tool surface versus a per-operation RBAC check on every request. Neither downscopes the Entra ID token — Azure has no primitive for that, and RBAC is evaluated server-side by Azure Resource Manager regardless.

> Third-party behavior was checked against official docs in June 2026; these tools change quickly, so re-verify before relying on this.

## Cynative configuration

### Target & connection settings

The Azure cloud the connector targets (shared with the `aks` connector). Default `auto` (detected via `AZURE_AUTHORITY_HOST` then the Azure CLI active cloud — see [Sovereign clouds](#sovereign-clouds)); pin it explicitly where auto-detection is unreliable.

```yaml
connectors:
  azure:
    cloud: auto   # or AzureCloud / AzureUSGovernment / AzureChinaCloud
```

```bash
export CYNATIVE_CONNECTORS_AZURE_CLOUD=auto
```

### Exposure & authorization settings

The Azure RBAC role definition the per-operation action gate authorizes against. Default `Reader`; see [Hardening](#hardening) for how it is applied.

```yaml
connectors:
  azure:
    role_definition: Reader
```

```bash
export CYNATIVE_CONNECTORS_AZURE_ROLE_DEFINITION=Reader
```

### Cache settings

The Azure service catalog is cached under `<cache.dir>/azure` (the role definition is fetched live per run, not cached). The cache is shared across connectors — see [Shared configuration](README.md#shared-configuration).

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

- Data-plane operations (Key Vault secrets, Blob/Queue/Table data, SQL/Cosmos data) are out of scope; Cynative is control-plane only and denies data-plane hosts at the network layer. The ARM control plane (`management.azure.com`) and data-plane services (for example Key Vault at `*.vault.azure.net`) use separate endpoints and separate token audiences ([control plane and data plane](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/control-plane-and-data-plane)).
- No per-session credential downscoping: there is no primitive to reduce an existing Entra ID access token's effective RBAC at request time — Azure RBAC is evaluated server-side by Azure Resource Manager per request ([Azure RBAC overview](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)).
- Sovereign cloud auto-detection is best-effort: it covers the Azure CLI / environment-variable credential sources but not managed identity on a sovereign host (whose cloud is exposed only via a network metadata probe Cynative does not make) — pin `connectors.azure.cloud` explicitly there. Custom / private / partner clouds (for example `login.partner.microsoftonline.cn`) and the retired Azure Germany cloud are not modeled; an unrecognized signal falls back to the public cloud. See [Sovereign clouds](#sovereign-clouds) and the vendor reference for [distinct ARM endpoints](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/control-plane-and-data-plane) and [Azure CLI cloud management](https://learn.microsoft.com/en-us/cli/azure/manage-clouds-azure-cli).
- Action authorization fails closed when operation or role-definition resolution fails.
- The Azure connector is for ARM control-plane APIs. Use `aks` for Kubernetes API calls to AKS clusters.
