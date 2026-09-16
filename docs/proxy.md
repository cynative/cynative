# Outbound proxies

Cynative honors the standard proxy variables for every connection a connector
makes: the requests the model issues through `http_request`, the startup
probes, the Kubernetes ClusterRole fetches, credential discovery and refresh,
and the authorization-data downloads (IAM policy documents, permission
catalogs, OpenAPI descriptions). One policy is read when the process starts and
every connector transport consults it. Nothing the model sends can change it.

## Variables

| Variable | Meaning |
|---|---|
| `https_proxy`, `HTTPS_PROXY` | proxy for `https://` targets, which is every connector request |
| `http_proxy`, `HTTP_PROXY` | proxy for `http://` targets; cynative itself issues none, some SDK metadata probes do |
| `no_proxy`, `NO_PROXY` | comma-separated list of targets that bypass the proxy |

The lower-case spelling wins when both are set and non-empty, the order
`curl` and Go's `x/net` use. A proxy value is one of:

```
http://proxy.corp:3128
http://user:password@proxy.corp:3128
socks5://proxy.corp:1080
socks5h://proxy.corp:1080
proxy.corp:3128            # no scheme means http
```

Both SOCKS spellings hand the unresolved destination name to the proxy; Go
never resolves the target locally for either. An `https://` proxy (TLS to the
proxy itself) is rejected at startup: Go would reuse the connector's TLS
settings (a cluster's private CA, an mTLS client certificate, a
`tls-server-name`) for the proxy hop, and no documentation makes that safe.
The startup error names the variable and the fault and never prints the value.

`NO_PROXY` entries: `*` (everything direct), an IP or CIDR (matched against a
request whose host is an IP literal only, never against what a name resolves
to), a host name (matches the name and its subdomains), a name with a leading
dot (subdomains only), and `host:port`. `localhost` in lower case and loopback
literals are never proxied. Trailing dots are significant on both sides: an
entry `api.example.com` does not match a request for `api.example.com.`.

## What crosses the proxy

| Traffic | Routed by the policy |
|---|---|
| `http_request` calls the model makes | yes, one route per request |
| GitHub and GitLab token probes at startup, OpenAPI description downloads | yes |
| EKS, GKE, AKS and self-managed Kubernetes ClusterRole fetches | yes |
| AWS SDK calls (STS, IAM, EKS, `AssumeRole`), the IAM policy document, the service reference and IAM dataset downloads | yes |
| Google ADC discovery and token refresh, the IAM roles service, the GKE service, the Discovery catalog, the tokeninfo probe | yes |
| Azure credential chain (environment, workload identity, managed identity), ARM role definitions, managed clusters, the ARM catalog | yes |
| Google Compute Engine metadata client (`169.254.169.254`) | no, link-local and never proxied, as in the SDK |
| `gh`, `glab`, `az`, `azd`, `pwsh` helper processes, an AWS `credential_process`, a Google executable-sourced credential | no, each is a separate process that inherits the environment and decides for itself |
| The model (LLM) connection | no, see below |

Instance metadata services reject proxied requests. On EC2 or Azure hosts add
the metadata address to `NO_PROXY`, as the vendors recommend:

```sh
export HTTPS_PROXY=http://proxy.corp:3128
export NO_PROXY=169.254.169.254,10.0.0.0/8,.corp.example
```

## Trust boundary

A direct connection, `NO_PROXY` matches included, keeps every check cynative
performs today: the host is pinned to the connector, the action is authorized,
the credential is attached only after both, and the resolved IP address is
verified before the connection is made.

A proxied connection keeps the host pin, the action authorization and the
credential injection, but the connection itself goes only to the proxy the
operator named. Cynative never resolves the destination and never verifies its
address; both are delegated to the proxy. That is the trust boundary change:

- The proxy sees the authority of every connection (`CONNECT host:port`).
- A plain CONNECT proxy cannot read the request inside the TLS tunnel; the
  origin certificate is verified against the connector's trust settings exactly
  as on a direct connection.
- An intercepting proxy, one whose certificate the trust settings accept, can
  read every credential cynative sends and rewrite every response. That
  includes the authorization data the client-side gate is built from: a
  rewritten ClusterRole, IAM policy or permission catalog widens what the
  gate allows. Only route cynative through a proxy you would trust with the
  credentials themselves.
- A proxy that refuses, resets or times out fails the request. Cynative never
  retries directly.

Proxy credentials in the URL are sent to the proxy as HTTP Basic (or SOCKS
authentication) over the plaintext proxy hop. They are never printed, and any
error text that echoes them is scrubbed before it reaches the model, the
inventory or the audit log.

## Certificate trust

Cynative verifies the origin certificate with the operating system's root
store plus the connector's own CA when it has one (the cluster CA from a
kubeconfig or the cloud API, `connectors.gitlab.ca_cert`). A TLS-intercepting
corporate proxy therefore works once its CA is in the OS store. On Linux, and
since Go 1.27 on macOS and Windows as well, `SSL_CERT_FILE` and `SSL_CERT_DIR`
replace the platform store rather than extend it, so a bundle named there must
contain the public roots too. No cynative option adds a CA; the existing
mechanisms cover the cases.

## Startup and audit

When a proxy is configured the connector inventory starts with one line:

```
  ~ egress      https_proxy http://proxy.corp:3128 · no_proxy 10.0.0.0/8,169.254.169.254
```

Every audited `http_request` result carries `route: "proxy"` or
`route: "direct"`, the route that was selected for it, whether or not the
connection then succeeded. A request denied before route selection (host,
action or credential rejection) carries no `route`.

An unusable setting stops the run before any connector registers:

```
  ✗ egress      HTTPS_PROXY: unsupported scheme "https"; use http://, socks5:// or socks5h://
```

## Local testing with an intercepting proxy

The same mechanism drives a connector against fixture responses without a
real backend. The recipe below uses mitmproxy in regular mode with an addon
that answers requests itself; cynative's own hermetic suite
(`test/proxy.smoke.test.sh`) does the same with a stdlib Python proxy.

1. Start the proxy with an addon that answers the endpoints you need:

   ```python
   # fixtures.py: answer the two endpoints a namespace listing needs and refuse
   # everything else, so an unscripted request fails loudly instead of leaving
   # the machine. The kubernetes connector fetches the ClusterRole at
   # registration, before any model request.
   from mitmproxy import http

   JSON = {"Content-Type": "application/json"}
   ROLE = b'{"kind":"ClusterRole","rules":[{"apiGroups":[""],"resources":["namespaces"],"verbs":["get","list"]}]}'
   NAMESPACES = b'{"kind":"NamespaceList","items":[{"metadata":{"name":"fixture"}}]}'

   def request(flow: http.HTTPFlow) -> None:
       if flow.request.host != "kube.example.test":
           flow.response = http.Response.make(403, b"unexpected host", JSON)
       elif flow.request.path == "/apis/rbac.authorization.k8s.io/v1/clusterroles/view":
           flow.response = http.Response.make(200, ROLE, JSON)
       elif flow.request.path == "/api/v1/namespaces":
           flow.response = http.Response.make(200, NAMESPACES, JSON)
       else:
           flow.response = http.Response.make(403, b"unscripted request", JSON)
   ```

   ```sh
   mitmdump --listen-port 8080 -s fixtures.py
   ```

2. Point the connector's trust at the proxy's CA. For the kubernetes connector
   put `~/.mitmproxy/mitmproxy-ca-cert.pem` into the kubeconfig's
   `certificate-authority-data`; for a connector that uses the system store,
   export `SSL_CERT_FILE` with a bundle that holds the public roots plus that
   certificate.

3. Run cynative in an isolated environment with fake credentials, so no real
   credential can reach the proxy and no real backend is contacted:

   ```sh
   cynative_bin="$(command -v cynative)"   # env -i drops PATH, so resolve it first
   env -i HOME="$(mktemp -d)" PATH=/usr/bin:/bin \
     KUBECONFIG=./fixture-kubeconfig \
     HTTPS_PROXY=http://127.0.0.1:8080 \
     AWS_EC2_METADATA_DISABLED=true \
     CYNATIVE_LLM_PROVIDER=... CYNATIVE_LLM_MODEL=... \
     "$cynative_bin" doctor
   ```

   The empty home keeps the cloud SDKs from finding real credentials; the
   proxy sees every `https` connection the run attempts and refuses the ones
   you did not script. Keep `NO_PROXY` unset so nothing bypasses the proxy. On
   a cloud VM the Google and Azure SDKs still probe their metadata services
   directly (plain `http`, never proxied); point `GCE_METADATA_HOST` and
   `MSI_ENDPOINT` at a loopback port that answers 400, as
   `test/proxy.smoke.test.sh` does, or run the test off the cloud.

## The model connection

The LLM connection is configured separately and is not changed by this
policy. Bifrost, the embedded LLM client, does not read the proxy variables;
its own `proxy_config` block (`type: http`, `socks5` or `environment`) governs
the model connection, and the Bedrock provider's client follows the proxy
variables through Go's default behavior. See `docs/providers/README.md`.
