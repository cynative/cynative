# GitLab connector

**Connector id:** `gitlab`
**Scope:** GitLab REST API (`/api/v4`) only. Supports both gitlab.com (the default) and self-managed GitLab instances. Non-`/api/v4` URLs (the web UI, `/-/jobs/artifacts/...`, `/uploads/...`, raw blob and release-asset download links) are not supported — fetch artifacts and releases through the `/api/v4` REST endpoints instead.

### Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | in-process per-request classification to a GitLab category + access level, allowed only within the configured ceiling (the GraphQL API is denied entirely) |
| Configurable exposure | ✓ · `connectors.gitlab.permissions` is a `category → read\|write\|none` ceiling (default read-only; ci-variables blocked) |
| Credential downscoping | — · GitLab has no runtime credential downscoping; token scopes are the global ceiling fixed at issue time |
| Host pinning | ✓ (configured `host` / `api_host`; one instance per run) |
| Dial-time IP authorization | ✓ (default internal-range deny; `allow_private_network: true` opt-in for self-managed private networks; loopback and link-local always denied) |
| Model-supplied-credential rejection | ✓ (incl. `Private-Token`, `Job-Token`, URL userinfo) |
| Response redaction | ✓ |

## Quick start

Authenticate with the GitLab CLI or export a Personal Access Token, then run Cynative from the same environment:

```bash
glab auth login
cynative -p "review my GitLab projects for exposed secrets"
```

Or with an explicit token:

```bash
export GITLAB_TOKEN=<read_api PAT>
cynative -p "list my GitLab merge requests"
```

No YAML is required for the default read-only mode against gitlab.com.

## Credential discovery

### Credential sources

Cynative resolves a token for the configured host (default `gitlab.com`) in this order:

1. **Token environment variable** — `GITLAB_TOKEN`, then `GITLAB_ACCESS_TOKEN`, then `OAUTH_TOKEN` (glab's precedence order); the first non-empty one is used, exec-free, and takes precedence over any glab credential.
2. **glab (`glab auth credential-helper`)** — when no token env var is set, cynative delegates to the pinned `glab` binary, which reads `config.yml` or the OS keyring, refreshes an expired OAuth token, and prints the credential as JSON. cynative selects the instance by setting `GITLAB_HOST` to the **login host** (the explicit `host`, or the `api_host` when only that is configured, never the un-configured `gitlab.com` default — so an `api_host`-only setup gets the api_host's own token, not the public one) and `GITLAB_API_HOST` to the configured `api_host`; it then validates that glab returned the login or api host's token. An explicit self-managed `host` paired with a separate `api_host` uses the login-host credential against the api host. See [OAuth token handling](#oauth-token-handling).

Cynative reads these variables to discover the GitLab token and locate glab's config:

- `GITLAB_TOKEN` — first-precedence token; exec-free and beats any glab credential.
- `GITLAB_ACCESS_TOKEN` — second-precedence token (glab precedence order).
- `OAUTH_TOKEN` — third-precedence token (glab precedence order).
- `GLAB_CONFIG_DIR` — exclusive override of glab's config directory; used to detect whether a glab config is present, and passed through to the glab child.
- `XDG_CONFIG_HOME` — adds `$XDG_CONFIG_HOME/glab-cli/config.yml` as a config location (when `GLAB_CONFIG_DIR` is unset). On macOS, `~/Library/Application Support/glab-cli/config.yml` (the OS-default config dir) is also detected — this is where `glab auth login` writes on macOS.

If no token env var is set and glab has no usable credential, the connector is a quiet ambient skip. If a glab config exists but the `glab` binary is missing or too old for the credential-helper, the connector is skipped **loudly** with a steer to install/upgrade glab or set `GITLAB_TOKEN`.

### Registration and validation

When a token is discovered, Cynative **validates it live at startup** with a dial-guarded `GET /api/v4/user` (which authenticates a PAT, project/group, or OAuth token) before registering — the same host-pinned, allow_private_network-aware, CA-aware path used at request time. So the startup connector inventory reflects reality:

- A **valid** token registers the connector and shows its identity as `@<username>` (and, for a self-managed instance, ` · <host>`), e.g. `✓ gitlab  read-only  @octocat`.
- An **invalid, expired, or unreachable** token shows the connector as unavailable with a reason, e.g. `✗ gitlab  …(token validation failed): gitlab API probe failed: status 401` — rather than registering and then failing every request.
- A genuinely **absent** token is a quiet ambient skip (nothing shown).

This matches the GitHub and Kubernetes connectors' validated-live registration.

> **Keyring supported.** glab users who authenticated with `--use-keyring` store
> their token in the OS keyring rather than in `config.yml`. Because cynative now
> delegates to `glab auth credential-helper` (see below), keyring-stored tokens work
> without any extra configuration.

#### OAuth token handling

For a glab credential, cynative delegates to `glab auth credential-helper` (the
machine-readable interface glab ships since v1.85.0; cynative runs it from a neutral
directory, which needs the non-git-folder host fallback added in **v1.85.2**). glab
reads `config.yml` or the OS keyring, refreshes an expired OAuth token within a grace
window, persists the rotation through its own atomic writer, and prints the credential
as JSON. cynative parses that JSON and caches the token until it nears expiry, then
re-runs the helper.

- **cynative never reads or writes glab's `config.yml`** and never holds the refresh
  token — glab owns the token lifecycle. A personal access token stored by glab is
  returned as-is and used for the session.
- **Self-managed OAuth** works the same way: glab owns the per-host OAuth client, so
  cynative needs no `client_id`.
- **Requires glab v1.85.2+.** A `config.yml` with no working `glab` on `PATH` (or a glab
  too old to resolve a host from a neutral directory) is skipped **loudly** with a steer
  to upgrade glab or set `GITLAB_TOKEN`. Set `GITLAB_TOKEN` for a fully exec-free path.
- **TLS trust is glab's.** glab performs its own OAuth-refresh TLS handshake using its
  own trust (the trust it authenticated the instance under at `glab auth login`).
  `connectors.gitlab.ca_cert` governs cynative's own request path, not glab's refresh, so
  a private-CA self-managed instance must be trusted by glab as well (which it is, having
  authenticated to it).
- **Hardened exec.** The binary is resolved once by absolute path, run with a fixed
  argv (never a shell), a curated child environment (cynative's own secrets are not
  passed through), a neutral working directory, a bounded timeout, and stdout/stderr
  size caps; the token is never echoed into any error.

### References

- [GitLab CLI (glab)](https://docs.gitlab.com/cli/) — `GITLAB_TOKEN` / `GITLAB_ACCESS_TOKEN` / `OAUTH_TOKEN` (auth tokens), `GLAB_CONFIG_DIR` (config dir); `glab auth login` stores the credential, and `glab auth credential-helper` (glab v1.85.2+, run from a neutral directory) is the machine-readable interface cynative delegates to. cynative sets `GITLAB_HOST`/`GITLAB_API_HOST` for the child to pin the instance.
- [GitLab personal access token scopes](https://docs.gitlab.com/user/profile/personal_access_tokens/) — `read_api` (least-privilege read), `api` (full), `read_repository`, `read_user`; the effective capability is the scope intersected with the permissions ceiling.

## Target selection

### Default target

The GitLab connector targets GitLab SaaS — `https://gitlab.com`, REST API `/api/v4` — by default. The instance is chosen by cynative config (`connectors.gitlab.host`, default `gitlab.com`) and host-pinned; the token for that host is discovered as described in [Credential discovery](#credential-discovery). The target is not selected per request (the URL must match the served host — `api_host` when set, otherwise `host`), and cynative does not read glab's own `GITLAB_HOST` / `GL_HOST` environment variables.

### Change the target

Point at a self-managed instance via cynative config: set `connectors.gitlab.host: gitlab.example.com` (or `CYNATIVE_CONNECTORS_GITLAB_HOST`). Optionally set `connectors.gitlab.api_host` to send API calls to a different host than the login host, append `:port` for a non-443 instance, set `connectors.gitlab.allow_private_network: true` for a private network, and `connectors.gitlab.ca_cert` for a private CA — see [Cynative configuration](#cynative-configuration). Supply a token for that host with `GITLAB_TOKEN` (highest precedence) or `glab auth login` — see [Credential discovery](#credential-discovery).

### Targeting inputs

Use `auth_provider: "gitlab"`. No connector-specific auth object is required — the target instance is chosen entirely by cynative config (`connectors.gitlab.host`/`api_host`), not per request. The request URL must match the served host (`api_host` when set, otherwise `host`); see [Request usage](#request-usage) for the full example.

## Request usage

### Required `http_request` args

Use `auth_provider: "gitlab"`. No connector-specific auth object is required.

### Minimal example

```js
const resp = await http_request({
  method: "GET",
  url: "https://gitlab.com/api/v4/projects",
  headers: [],
  body: "",
  auth_provider: "gitlab"
});
console.log(resp.body);
```

For self-managed instances, replace `gitlab.com` with your configured `host` (or `api_host`).

## Hardening

Cynative's GitLab connector is built for read-oriented source-and-repository research. By default it combines an in-process per-request classifier — resolving each request to its GitLab category and required access level — with host pinning, dial-time IP authorization, and response redaction before output returns to the model.

Like the cloud connectors — where `connectors.aws.policy`, `connectors.gcp.role`, and `connectors.azure.role_definition` tune exposure along a spectrum — GitLab's exposure is configurable through `connectors.gitlab.permissions`, a `category → read|write|none` ceiling. The secure default is read-only with `ci-variables` blocked; widen a single category to `write` (or open `ci-variables`) only where a workflow needs it. The effective capability is always the intersection of this ceiling and the token's own scopes, so prefer a minimally-scoped token as well.

### Checks before the token is attached

- Cynative rejects any non-`https` URL, so credentials never traverse plaintext.
- Requests carrying a model-supplied credential fail closed — the connector is the sole setter of credential material. This covers: the `Private-Token`, `Job-Token`, `Deploy-Token`, `X-Gitlab-Static-Object-Token`, `Authorization`, `Proxy-Authorization`, `X-Ms-Authorization-Auxiliary`, and `Cookie` headers; URL userinfo (`user:pass@`); the GitLab request-parameter credentials `token` (pipeline-trigger/runner), `private_token`, `access_token`, and `job_token` — rejected in the query string **and** in a urlencoded, multipart, or JSON request body (the encodings GitLab reads into `params`); the `feed_token`/`rss_token` feed credentials in the query string; and the `sudo` impersonation control (`sudo` query parameter or `Sudo` header), which is blocked regardless of the exposure ceiling. Credential header names are matched with `_`/`-` normalized, so a Rack-folded underscore variant (e.g. `Private_Token`) is rejected too, and credential **query/body** parameters are matched on their base name, so a Rack bracket form (e.g. `private_token[]`) is rejected like `private_token`.

### Host pinning

Host pinning allows only the configured `host` (default `gitlab.com`), or `api_host` when set. Requests to any other host are rejected. Because the credential is attached to every request, every allow-listed host must be the operator-configured GitLab instance.

The request's TLS **port** is pinned too: both the request URL's port and a model-supplied `Host` header override's port must match the configured `host`/`api_host` port (or `443` when none is configured). This stops a request from attaching the Bearer token to a different service co-located on the same host/IP at another port. For a self-managed instance on a non-default port, configure it as `host: gitlab.internal:8443`.

The connector serves the `/api/v4` REST API only. A request whose path is not under `/api/v4` — a web-UI page or a `/-/jobs/artifacts/...`, `/uploads/...`, or `/<group>/<project>/-/raw/...` download link — is not category-classifiable and fails closed (`ErrUnclassifiable`), regardless of the configured ceiling. Use the `/api/v4` artifact and release REST endpoints to fetch those resources instead.

Redirects are never followed. A 3xx is returned to the model, which must request the `Location` URL explicitly — re-entering host pinning and action authorization on each hop.

### Per-category exposure classification

Read-only is the default. The in-process classifier resolves each REST request to its GitLab category and the access level it requires (read or write), then allows it only when the configured `connectors.gitlab.permissions` ceiling permits that level for that category. The check runs **before** the token is attached, so a disallowed request is rejected without the credential ever leaving the process. Reads are `GET`, `HEAD`, `OPTIONS` (plus the `POST /api/v4/markdown` documentation-render endpoint); everything else is a write.

The classifier is backed by GitLab's first-party OpenAPI v3 description (distilled into a category routing table, fetched anonymously and cached from `gitlab.com`); a REST request that cannot be classified, or a configured permissions key that matches no real GitLab category, fails closed. The `ci-variables` category is denied by the secure baseline (even for reads) because its read endpoints return plaintext CI/CD variable values; open it explicitly only when needed. Because GitLab tags variable endpoints inconsistently (the tag scatters across CI variables / Pipelines / Pipeline schedules), any OpenAPI **template** whose path contains a `variables` segment is mapped to the `ci-variables` category at table-distillation time, regardless of the operation's own tag. This operates on the trusted spec templates rather than the request path, so a `variables` value appearing in a path *parameter* (for example a repository file named `variables`) keeps its true category and does not inherit the `ci-variables` ceiling. A fetched or cached spec that maps a `variables` template to a non-variable category is rejected at admission. The GraphQL API (`/api/graphql`) is not supported and is always denied; use the REST API.

### Dial-time IP authorization

The transport resolves the configured host's IP addresses at dial time and pins each connection to that resolved IP set. By default, internal IP ranges (RFC1918, loopback, link-local including the cloud metadata address `169.254.169.254`, ULA, and IPv4-mapped forms) are denied. This prevents DNS-rebinding and SSRF attacks.

For self-managed GitLab instances on private networks (e.g. `10.0.0.0/8`), set `allow_private_network: true`. The opt-in re-permits **RFC1918 IPv4** (and global-unicast IPv6). An unconditional floor remains denied even with the opt-in enabled: loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`, including cloud metadata), the exact IPv4 cloud host-local addresses, and **all private (ULA) IPv6 (`fc00::/7`)**. ULA IPv6 stays denied because every major cloud parks its IPv6 instance-metadata service there (AWS `fd00:ec2::254`, GCP `fd20:ce::254`, OCI, Alibaba, Scaleway), and the exact-IP pin alone does not stop a DNS rebind onto a metadata address (a rebind moves both the dial resolution and the pin re-resolution together) — so the floor, not the pin, is the rebind defense. A self-managed GitLab reachable only on a ULA IPv6 address is therefore unsupported; front it with an RFC1918 IPv4 or global-unicast IPv6 address.

### CA certificate (self-managed with a private CA)

Set `connectors.gitlab.ca_cert` to the path of a PEM CA certificate file. Cynative reads and applies it for all connections to the configured host, including the eager token-validation probe. `skip_tls_verify` is **not supported** — TLS validation cannot be bypassed.

### Credential injection

After all checks pass, Cynative injects an `Authorization: Bearer <token>` header. Bearer is used (rather than `PRIVATE-TOKEN`) because it authenticates **both** Personal/project/group access tokens **and** OAuth tokens — and `glab auth login` on gitlab.com defaults to an OAuth token, which `PRIVATE-TOKEN` would reject with a 401. The token is never attached when a request is denied by the exposure ceiling.

### Least-privilege tokens

**GitLab roles are server-side and per-resource, not a client-side gate.** Scopes are the global ceiling on what the token can do, but they do not replace server-side role checks (e.g. Developer vs. Reporter). For a strong least-privilege posture, pair the read-only `permissions` default with a read-only service-account or bot-user identity that has at most Reporter-level role on the projects it needs to access, and issue the token with the narrowest scopes the workflow requires.

### Response redaction

Cynative redacts secret-shaped content and credential-named fields from responses before the model sees them, and blanks credential response headers wholesale — including `Set-Cookie`, `Authorization`, `Private-Token`, `Job-Token`, `Deploy-Token`, and `X-Gitlab-Static-Object-Token`. Redaction is a defense-in-depth layer, not a reason to treat returned GitLab data as public.

### Reading the posture

The startup connector inventory line for GitLab shows the access level, enforcement locus, and configured ceiling, for example:

```text
✓ gitlab access=default(read-only) · enforced=client · permissions=default=read,ci-variables=none · @user
```

- `access=default(read-only)` when no `connectors.gitlab.permissions` override is configured (the secure baseline is in force); `access=custom` when any override is set.
- `enforced=client` — the in-process per-request classifier is an active control that gates every request before the token is attached; the model receives the effective ceiling in its system prompt.
- `permissions=<effective-ceiling>` — the configured ceiling verbatim.

When the ceiling is widened — `default=write`, an opened `ci-variables`, or any `category:write` override — the line is loud (`⚠`) and names exactly what was widened, so broadening exposure is never silent.

When the category routing table cannot be resolved (no network **and** no local cache), the connector fails closed: every classification-dependent request is denied with a `gitlab_hardening: category table not ready` error returned to the model.

## Cynative configuration

### Target & connection settings

Configure the GitLab instance cynative connects to. The defaults target gitlab.com with standard HTTPS on port 443.

```yaml
connectors:
  gitlab:
    host: gitlab.com            # optional; default is gitlab.com
    api_host: ""                # optional; overrides the host used for API requests
    allow_private_network: false  # set true for self-managed instances on private networks
    ca_cert: ""                 # path to a PEM CA file for self-managed instances with a private CA
```

```bash
export CYNATIVE_CONNECTORS_GITLAB_HOST=gitlab.example.com
export CYNATIVE_CONNECTORS_GITLAB_API_HOST=api.gitlab.example.com
export CYNATIVE_CONNECTORS_GITLAB_ALLOW_PRIVATE_NETWORK=false
export CYNATIVE_CONNECTORS_GITLAB_CA_CERT=/path/to/ca.pem
```

`host` is the login host (the key glab uses in `config.yml`). Requests are served and pinned to the **served host** — `api_host` when set, otherwise `host` — so set `api_host` when API calls go to a different host than the login host (e.g. a load balancer in front of the Rails app). Append `:port` to either for a non-443 instance (e.g. `host: gitlab.internal:8443`). `allow_private_network: true` re-permits RFC1918 dials; the ULA-IPv6 floor remains. `ca_cert` is the path to a PEM CA file for private-CA instances (TLS validation cannot be bypassed — `skip_tls_verify` is not supported).

### Exposure & authorization settings

`connectors.gitlab.permissions` is a `category → read|write|none` ceiling; see [Hardening](#hardening) for how it is applied. Omit it entirely for the secure default (read everything except `ci-variables`).

```yaml
connectors:
  gitlab:
    permissions:                # optional; omit entirely for the secure read-only baseline
      default: read             # baseline ceiling for every category (read|write|none)
      projects: write           # widen a single category to write
      ci-variables: read        # opt back in to a category the baseline blocks
```

Each key is `default` or a GitLab category (the normalized OpenAPI tag, e.g. `projects`, `merge-requests`, `ci-variables`); a category lookup falls back to `default`. `write` implies `read`; `none` denies even reads. Keys are validated for shape at load time and checked against the live GitLab category table at request time, failing closed on a typo.

`permissions` can also be set from the environment as a compact, comma-separated list of `key=value` pairs:

```bash
export CYNATIVE_CONNECTORS_GITLAB_PERMISSIONS="default=read,projects=write,ci-variables=none"
```

A non-empty env value **replaces** the config-file map wholesale — it is not merged — and, like the file form, can widen the ceiling, so the startup inventory connector line is loud (`⚠`) when it sets `default=write` or opens `ci-variables`. A blank value is treated as unset, leaving the file map in place.

### Cache settings

The GitLab OpenAPI category routing table is fetched anonymously from `gitlab.com` and cached under `<cache.dir>/gitlab`. The cache is shared across connectors — see [Shared configuration](README.md#shared-configuration).

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

- **CI job tokens** (endpoint-restricted) are out of scope. Cynative authenticates via `Authorization: Bearer`, which accepts Personal Access Tokens (PATs), project/group access tokens, **and** OAuth tokens (including the OAuth token `glab auth login` stores by default). OAuth access tokens have a 2-hour lifetime; `glab auth credential-helper` refreshes them on demand, so a long session keeps working.
- **The category routing table needs egress to `gitlab.com`.** The classifier is backed by GitLab's first-party OpenAPI v3 spec, live-fetched anonymously and cached under `~/.cynative/cache/gitlab`. With no network **and** no local cache the connector fails closed (every classification-dependent request is denied). A self-managed version lag may over-deny renamed endpoints (the spec is fetched from gitlab.com `master` for both gitlab.com and self-managed instances) — fail-closed by design.
- **Container Registry and Pages** use separate hosts and authentication paths not covered by this connector. The connector pins to the configured GitLab API host only.
- **Subpath-mounted installations** (e.g. `https://example.com/gitlab/`) are not supported. Cynative assumes the API is at the host root (`/api/v4`).
- **A glab credential requires the `glab` binary** (v1.85.2+, for `glab auth credential-helper` run from a neutral directory) on `PATH`. cynative delegates discovery and refresh to glab rather than parsing `config.yml` itself, so keyring-stored tokens work but a `config.yml` with no usable glab is skipped loudly. Set `GITLAB_TOKEN` for a fully exec-free path.
- **`skip_tls_verify` is not supported.** TLS validation cannot be bypassed. Use `ca_cert` to supply a custom CA for self-managed instances with a private certificate authority.
- **One instance per run.** Cynative registers at most one GitLab provider per session, bound to the configured `host`. Accessing multiple GitLab instances in the same session is not supported.
- **No runtime credential downscoping.** GitLab has no server-side API to exchange a token for a reduced-scope credential. The token's scopes are fixed at issue time. The `permissions` ceiling narrows what cynative will attempt but never expands the token's own scopes — the effective capability is the intersection of the two. Pair a minimally-scoped token (e.g. `read_api` only) and a read-only service-account identity with the read-only `permissions` default for the strongest least-privilege posture.
- **Private (ULA) IPv6 instances are unsupported even with `allow_private_network: true`.** The unconditional dial floor denies `fc00::/7` because that is where every cloud's IPv6 metadata service lives and the exact-IP pin does not stop a DNS rebind onto it. Reach a self-managed instance over RFC1918 IPv4 or a global-unicast IPv6 address instead.
- **A literal `token` field in a request body is rejected.** GitLab reads `params[:token]` (the pipeline-trigger credential) from a urlencoded, multipart, or JSON body, so any model-supplied `token` field is treated as a smuggled credential and fails closed — regardless of the exposure ceiling. As a result, configuring a resource whose own data carries a field literally named `token` (e.g. a webhook secret token) via this connector is not supported. Trigger pipelines with the Bearer-authenticated `POST /projects/:id/pipeline` endpoint instead of `POST /projects/:id/trigger/pipeline`.
