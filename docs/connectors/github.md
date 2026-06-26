# GitHub connector

**Connector id:** `github`
**Scope:** GitHub REST API on `api.github.com`, plus the GitHub-owned download hosts `codeload.github.com`, `release-assets.githubusercontent.com`, and `objects.githubusercontent.com` (GET/HEAD only).

### Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ (secret-scanning blocked even for reads) |
| Enforcement model | in-process per-request classification to a GitHub category/subcategory + access level, allowed only within the configured ceiling |
| Configurable exposure | ✓ · `connectors.github.permissions` is a `category[/subcategory] → read\|write\|none` ceiling (default read-only; secret-scanning blocked) |
| Credential downscoping | — · user tokens can't be downscoped at runtime (a GitHub App path is a possible future direction) |
| Host pinning | ✓ (`api.github.com` + GitHub-owned download hosts, GET/HEAD) |
| Dial-time IP authorization | ✓ (default internal-range deny) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Quick start

Authenticate the GitHub CLI, then run Cynative from the same environment:

```bash
gh auth login
cynative -p "review my GitHub repositories for exposed secrets"
```

No YAML is required for the default read-only mode.

## Credential discovery and eager validation

### Credential sources

Cynative asks the GitHub CLI auth library ([go-gh](https://github.com/cli/go-gh)) for a token for `github.com`. Cynative does not read these variables itself; go-gh does. Because cynative always queries the literal `github.com` host, go-gh's enterprise / `GH_HOST` branches never apply.

- `GH_TOKEN` — highest-precedence GitHub token; read by go-gh for `github.com` and used as cynative's identity.
- `GITHUB_TOKEN` — second-precedence token (also the GitHub Actions built-in token).
- `GH_PATH` — path to the `gh` executable go-gh shells out to for the keyring-fallback token lookup.
- `GH_CONFIG_DIR` — directory go-gh reads the `gh auth login` token (`hosts.yml`) from.

### Registration and validation

If no token is available, the connector is not registered and nothing is printed (a silently-absent token is the expected ambient state).

When a token is present, Cynative **eagerly validates it at startup** before registering the connector. The probe is a hardened `GET /user` request, which also yields the `@login` identity shown in the startup connector inventory. When `/user` is inconclusive — a GitHub App installation token, an Actions `GITHUB_TOKEN`, or a `/user`-specific rate-limit may return 401/403 — Cynative falls back to `GET /rate_limit`, a universally-accessible, rate-limit-exempt endpoint that confirms the token is live without revealing identity. The fallback returns no identity; the connector still registers successfully.

Both probe requests travel over a **github-specific public-internet dial guard** (`githubDialAllowed`) that is stricter than the default internal-range deny: it additionally blocks special-use ranges including CGNAT (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), `0.0.0.0/8`, IETF/protocol assignments (`192.0.0.0/24`), 6to4-relay anycast (`192.88.99.0/24`), `240.0.0.0/4`, and any non-global-unicast address. It also denies IPv4-embedding IPv6 addresses — NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) — when the embedded IPv4 is internal, so a DNS-rebound AAAA that smuggles a metadata/RFC1918 address through an IPv6 wrapper is rejected (a NAT64-wrapped *public* github IPv4 stays allowed, so IPv6-only/DNS64 hosts still work). Redirects are never followed during the probe. Together these ensure a DNS-rebound `api.github.com` can never receive the bearer token, even in environments where internal RFC1918 addresses are reachable.

An invalid, expired, or unreachable token causes the connector to show **unavailable** in the startup inventory with a reason (`token validation failed: …`). A transient error (network timeout, 5xx, 429) is retried once before the connector is skipped.

### References

- [GitHub CLI environment variables](https://cli.github.com/manual/gh_help_environment) — `GH_TOKEN` / `GITHUB_TOKEN` (auth token), `GH_PATH` (gh executable), `GH_CONFIG_DIR` (config location).
- [Authenticating to the GitHub REST API](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api) — the `api.github.com` base URL, `Authorization: Bearer`, fine-grained vs classic personal access tokens; token scopes determine the effective capability (intersected with the permissions ceiling).

## Target selection

### Default target

The GitHub connector always targets the public GitHub REST API at `api.github.com` — the host is hardcoded, and GitHub Enterprise Server is not supported. It additionally authorizes the GitHub-owned download hosts `codeload.github.com`, `release-assets.githubusercontent.com`, and `objects.githubusercontent.com` (GET/HEAD only) so release-asset and tarball redirects can be followed. The *identity* is the token resolved at startup (see [Credential discovery](#credential-discovery-and-eager-validation)); neither the host nor the identity is selected per request — `auth_provider: "github"` only selects the connector.

### Change the target

The host is not configurable. Change the identity by changing the token cynative resolves: run `gh auth login`, or export `GH_TOKEN` (highest precedence), or `GITHUB_TOKEN` (see [Credential discovery](#credential-discovery-and-eager-validation) for the full token precedence). Prefer a minimally-scoped fine-grained personal access token. To change what the connector is *allowed* to do (not where it points), set the exposure ceiling under [Cynative configuration](#cynative-configuration) (`connectors.github.permissions`).

### Targeting inputs

Each request selects the connector with `auth_provider: "github"`. No per-request auth object is required or supported — the host and identity are fixed at startup. See [Request usage](#request-usage) for the full call schema.

## Request usage

### Required `http_request` args

Use `auth_provider: "github"`. No connector-specific auth object is required.

### Minimal example

```js
const resp = await http_request({
  method: "GET",
  url: "https://api.github.com/user",
  headers: [],
  body: "",
  auth_provider: "github"
});
console.log(resp.body);
```

## Hardening

Cynative's GitHub connector is built for read-oriented source-and-repository research with controls around every model-authored request. By default it combines an in-process per-request classifier — resolving each request to its GitHub category/subcategory and required access level — with host pinning, dial-time IP authorization, and response redaction before output returns to the model.

Like the cloud connectors — where `connectors.aws.policy`, `connectors.gcp.role`, and `connectors.azure.role_definition` tune exposure along a spectrum — GitHub's exposure is configurable through `connectors.github.permissions`, a `category[/subcategory] → read|write|none` ceiling. The secure default is read-only with secret-scanning blocked; widen a single category to `write` (or open `secret-scanning`) only where a workflow needs it. The effective capability is always the intersection of this ceiling and the `gh` token's own scopes, so prefer a minimally-scoped fine-grained PAT for the `gh` login as well.

### Checks before the token is attached

- Cynative rejects any non-`https` URL, so credentials never traverse plaintext.
- Requests carrying a model-supplied credential in an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fail closed.

### Host pinning

Host pinning allows `api.github.com` and the three GitHub-owned download hosts above. The download hosts are GET/HEAD-only, regardless of the configured permissions. Every allow-listed host must be GitHub-operated because the gh token is injected on every one of them.

Redirects are never followed. A 3xx is returned to the model, which must request the `Location` URL explicitly — re-entering host pinning and action authorization (and, for direct tool calls, the approval prompt; inside an approved `code_execution` script, the hop runs under that script's one-time approval). This keeps tarball/release-asset downloads working (their targets are allow-listed) while Actions-artifact downloads (redirects to per-account Azure blob storage) are denied.

### Category + access-level classification

Read-only is the default. The in-process classifier resolves each REST request to its GitHub category/subcategory and the access level it requires (read or write), then allows it only when the configured `connectors.github.permissions` ceiling permits that level for that category. The GraphQL API (`/graphql`) is not supported and is always denied; use the REST API. The check runs **before** the token is attached, so a disallowed request is rejected without the credential ever leaving the process. The classifier is backed by GitHub's first-party OpenAPI description (distilled into a category routing table, fetched anonymously and cached from `raw.githubusercontent.com`); a REST request that cannot be classified, or a configured permissions key that matches no real GitHub category, fails closed. The `secret-scanning` category is denied by the secure baseline (even for reads) because its read endpoints can leak secret material; open it explicitly only when needed. Secret-scanning protection is layered: the table admission guard rejects any fetched spec that maps a `secret-scanning` template to another category, the `secret-scanning: none` baseline in the default Exposure blocks all such requests at the ceiling, and unknown routes fail closed — no request-time segment scan is needed or used (a segment scan would match user-controlled positions like an owner or branch named "secret-scanning").

#### Egress dependency and fail-closed behavior

The category routing table is live-fetched from `raw.githubusercontent.com` and cached under `<cache.dir>/github`. The connector needs egress to `raw.githubusercontent.com`; with no network **and** no local cache, the connector fails closed — every `api.github.com` request is denied with a `github_hardening: category table not ready` error returned to the model. This matches how the cloud connectors fail closed without access to their vendor-hosted specification. Enterprise egress allow-lists that permit `api.github.com` but block the CDN should also allow `raw.githubusercontent.com`, or pre-prime the cache with one online run.

A post-response advisory audit compares GitHub's authoritative `X-Accepted-GitHub-Permissions` response header against the classification and logs a one-line `github_hardening:` drift warning if a request classified as read appears to have needed more — defense-in-depth against an under-classification. It never blocks (the response already returned).

### Credential injection

After host and action checks pass, Cynative injects `Authorization: Bearer <token>` and strips any model-supplied `X-GitHub-Api-Version` header, letting GitHub use its current default version. The category routing table is fetched from the live `main` branch of GitHub's OpenAPI description, so removing the pinned constant keeps the table and the wire behaviour aligned without diverging over time.

### Response redaction

Cynative redacts secret-shaped content and credential-named fields from responses before the model sees them. Redaction is a defense-in-depth layer, not a reason to treat returned GitHub data as public.

### Reading the posture

The startup connector inventory line for GitHub shows the access level, enforcement locus, and configured ceiling, for example:

```text
✓ github access=default(read-only) · enforced=client · permissions=default=read,secret-scanning=none · @user
```

- `access=default(read-only)` when no `connectors.github.permissions` override is configured (the secure baseline is in force); `access=custom` when any override is set.
- `enforced=client` — the in-process per-request classifier is an active control that gates every request before the token is attached; the model receives the effective ceiling in its system prompt.
- `permissions=<effective-ceiling>` — the configured ceiling verbatim.

When the ceiling is widened — `default=write`, an opened `secret-scanning`, or any `category:write` override — the line is loud (`⚠`) and names exactly what was widened, so broadening exposure is never silent.

When the category routing table cannot be fetched (no network and no local cache), the connector still registers and its line shows the configured `permissions=` ceiling, but every `api.github.com` request is denied at request time with a `github_hardening: category table not ready` error until the table becomes available.

### How this compares to read-only alternatives

The official [GitHub MCP server](https://github.com/github/github-mcp-server/blob/main/README.md) ships a read-only mode — enabled with the `--read-only` flag, the `GITHUB_READ_ONLY=1` env var, or a `/readonly` URL suffix — enforced **server-side by tool gating**: write tools are simply omitted from the tool list the model can see.

Cynative enforces exposure differently: rather than omitting tools, an in-process classifier resolves each request to its GitHub category and access level and allows it only within the configured `permissions` ceiling (read-only by default, with secret-scanning blocked), backed by host pinning. The GitHub MCP server gates at its own tool surface; Cynative gates each request in-process — two different points in front of the same API. Neither downscopes the user token: the credential stays as broad as it was issued.

> Third-party behavior was checked against official docs in June 2026; these tools change quickly, so re-verify before relying on this.

## Cynative configuration

### Exposure & authorization settings

`connectors.github.permissions` is a `category[/subcategory] → read|write|none` map. Omit it entirely for the secure default (read everything except `secret-scanning`). Each key is `default`, a GitHub category, or a `category/subcategory`; the most-specific match wins (`category/subcategory` → `category` → `default`). `write` implies `read`; `none` denies even reads.

```yaml
connectors:
  github:
    permissions:
      default: read            # baseline for unlisted categories (default: read)
      issues: write            # allow creating/editing issues
      pulls: write             # allow opening/merging PRs
      secret-scanning: read    # opt back in to a category the baseline blocks
      actions/secrets: none    # deny a single subcategory outright
```

`permissions` can also be set from the environment as a compact, comma-separated list of `key=value` pairs:

```sh
export CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS="default=read,issues=write,secret-scanning=none"
```

A non-empty env value **replaces** the config-file map wholesale — it is not merged — and, like the file form, can widen the ceiling, so the startup inventory connector line is loud (`⚠`) when it sets `default=write` or opens `secret-scanning`. A blank (empty or whitespace-only) value is treated as unset, so it leaves the config-file map in place rather than silently resetting the ceiling; to tighten back to the baseline, set an explicit value (e.g. `default=read`) or remove the file entry. A duplicate key (e.g. `issues=none,issues=write`) is rejected at load time rather than silently taking the last value. Both forms are validated at load time (`read|write|none` and a well-formed key); keys are additionally checked against the live GitHub category table at request time and fail closed on a typo. The effective capability is the intersection of this ceiling and the `gh` token's own scopes, so still prefer a minimally-scoped fine-grained PAT.

### Cache settings

The GitHub category routing table (distilled from GitHub's OpenAPI description) is cached under `<cache.dir>/github`. The cache is shared across connectors — see [Shared configuration](README.md#shared-configuration).

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

- The connector supports `api.github.com` and the listed download hosts; [GitHub Enterprise Server](https://docs.github.com/en/enterprise-server@latest/admin/overview/about-github-enterprise-server) hosts are not registered by this connector.
- Actions-artifact downloads are not supported: GitHub [redirects them to per-account Azure blob endpoints](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact), which are outside the GitHub-owned host invariant (the gh token is injected on every allow-listed host).
- A configured `permissions` ceiling never *expands* the GitHub token's own scopes — the effective capability is the intersection of the two. Setting `issues: write` does nothing if the `gh` token cannot write issues; it only ever narrows what cynative will attempt. Scope the `gh` token minimally.
- There is no client-side credential downscoping for GitHub. A user [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens), `gh`, or OAuth token has its scopes fixed at creation and cannot be exchanged for a reduced-scope token at runtime, so cynative wields the full token. (By contrast, [GitHub App installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) *can* be scoped at runtime, so an App-based design could downscope; that remains a possible future direction.)
- Cynative does not create or narrow the GitHub token. Configure token scopes through GitHub and `gh`.
