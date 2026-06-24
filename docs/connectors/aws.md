# AWS connector

**Connector id:** `aws`
**Scope:** AWS service APIs signed with SigV4.

### Defense at a glance

| Control | Status |
|---|---|
| Read-only by default | ✓ |
| Enforcement model | IAM action simulation (`iam:SimulateCustomPolicy`) against the configured policy |
| Configurable exposure | ✓ any IAM policy ARN (default `SecurityAudit`); the choice is also enforced server-side via the STS scope for assumed-role identities |
| Credential downscoping | ✓ STS-scoped session, AWS-side — assumed-role identities only (`sts=assume_role`); IAM-user and root run unscoped |
| Host pinning | ✓ (host→service/region; rejects IP literals, localhost, VPC endpoints) |
| Dial-time IP authorization | ✓ (default internal-range deny) |
| Model-supplied-credential rejection | ✓ |
| Response redaction | ✓ |

## Quick start

Run Cynative from a shell where the AWS SDK default credential chain can retrieve credentials:

```bash
aws sts get-caller-identity
cynative -p "list public S3 buckets in my AWS account"
```

## Credential discovery

### Credential sources

Cynative loads AWS config through the AWS SDK default config chain and probes credential retrieval. The SDK can use standard sources such as environment variables, shared config and credentials files, SSO-backed profiles, web identity, ECS credentials, and EC2 instance roles. The SDK chain reads these variables — cynative does not read them to authenticate; it inspects the credential/profile/role/file ones only as a startup presence signal for skip-logging:

- `AWS_PROFILE` — selects the named shared-config/credentials profile (also implies the target account; see [Target selection](#target-selection)).
- `AWS_DEFAULT_PROFILE` — legacy profile selector, lower precedence than `AWS_PROFILE`.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` — static or temporary credentials.
- `AWS_ROLE_ARN` / `AWS_WEB_IDENTITY_TOKEN_FILE` — web-identity role to assume.
- `AWS_CONFIG_FILE` / `AWS_SHARED_CREDENTIALS_FILE` — override the `~/.aws/config` and `~/.aws/credentials` paths.
- `AWS_CA_BUNDLE` — TLS CA bundle the AWS SDK uses for cynative's **own** AWS control calls (credential retrieval, STS `AssumeRole` (assumed-role identities), IAM policy fetch). It is **not** applied to the guarded transport that serves the model's AWS `http_request` calls, so a TLS-intercepted environment can still fail those — it is neither a credential nor a target.

### Registration and validation

Cynative then **eagerly validates** the credential at startup with `sts:GetCallerIdentity` — the liveness check that also yields the `account · arn` identity shown in the startup inventory (ctx-bounded, retried once on a transient error). If config loading, credential retrieval, or that identity check fails, the AWS and EKS connectors are not registered — the skip is shown (as unavailable at startup) only when AWS was explicitly configured or under `--verbose`; an ambient credential-less environment is skipped quietly.

### References

- [AWS CLI environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html) — `AWS_PROFILE`, static credentials, `AWS_ROLE_ARN` / `AWS_WEB_IDENTITY_TOKEN_FILE`, file-location variables, `AWS_CA_BUNDLE` (the region variables are under [Target selection](#target-selection)).
- [AWS CLI configuration and credential files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) — named / `[default]` profiles and the `~/.aws/config` + `~/.aws/credentials` locations the SDK default chain reads.

## Target selection

### Default target

The connector signs as whatever account/identity the AWS SDK default chain resolves (see [Credential discovery](#credential-discovery)) — cynative does not pick an account itself. Region is supplied per request via `aws_auth.region`: a regional endpoint requires it to be present and to match the request host (host authorization rejects an empty or mismatched region), while a partition-global endpoint (for example IAM or global STS) accepts an empty or canonical region — and only when the region is **omitted** does signing fall back to the SDK-resolved region (`AWS_REGION` / `AWS_DEFAULT_REGION` / profile, default `us-east-1`); a region you do supply is used as given.

### Change the target

Change the account/identity exactly as you would for the `aws` CLI — select a profile with `export AWS_PROFILE=<name>`, set static credentials, point at a role, or relocate the credential files (the full variable set is under [Credential discovery](#credential-discovery)); verify with `aws sts get-caller-identity`. Change the default region with `AWS_REGION` (which overrides `AWS_DEFAULT_REGION`), or have the model pass `aws_auth.region` per request (which wins, and must match the request host). `connectors.aws.policy` changes the IAM exposure ceiling, not the targeted account or region — see [Cynative configuration](#cynative-configuration).

### Targeting inputs

The service and region for each call come from the per-request `aws_auth` object — `aws_auth.service` (required) and `aws_auth.region`; see [Request usage](#request-usage) for the full schema. For a **regional** endpoint the region must be present and match the request host: host authorization rejects an empty or mismatched claim before signing, so omitting it and relying on `AWS_REGION` does **not** work there. For a **partition-global** endpoint the region may be omitted; signing then uses the SDK-resolved region (`AWS_REGION`, which overrides `AWS_DEFAULT_REGION`), defaulting to `us-east-1`.

## Request usage

### Required `http_request` args

Use `auth_provider: "aws"` and include:

```json
{
  "aws_auth": {
    "service": "ec2",
    "region": "us-east-1"
  }
}
```

`aws_auth.service` is required. `aws_auth.region` should be supplied for regional endpoints and must match the request host. Signing can fall back to the SDK-configured or default region after host authorization passes.

### Minimal example

```js
const resp = await http_request({
  method: "GET",
  url: "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
  headers: [],
  body: "",
  auth_provider: "aws",
  aws_auth: { service: "sts", region: "us-east-1" }
});
console.log(resp.body);
```

## Hardening

Cynative's AWS connector is built for read-oriented cloud research with controls around every model-authored request. The default path combines client-side checks with AWS-side enforcement where available: an assumed-role STS session when applicable, host pinning, policy-aware action authorization, and response redaction before output returns to the model.

The default AWS policy is `arn:aws:iam::aws:policy/SecurityAudit`, an AWS-managed policy intended for security audit reads. You can configure a different managed policy with `connectors.aws.policy`.

### Baseline checks before signing

Two baseline protections apply before any request is sent:

- Cynative rejects any non-`https` URL, so credentials never traverse plaintext.
- Requests with model-supplied credentials in an `Authorization`, `Proxy-Authorization`, or `X-Ms-Authorization-Auxiliary` header, or URL userinfo (`user:pass@`), fail closed.

Cynative signs requests with AWS SigV4 only after these and the hardening checks below pass.

### Credential scoping (AWS-side)

For **assumed-role identities**, Cynative re-vends the credentials via STS `AssumeRole` for a one-hour session scoped to the configured policy. The resulting permission set is the role's policies intersected with the configured policy. With the default `SecurityAudit` policy, the agent runs a credential intended for security-audit reads. With any read-only configured policy, AWS IAM becomes a server-side backstop for assumed-role callers: if a mutating action slips past the client-side action gate, the scoped credential normally still cannot perform it.

**IAM-user and root identities run unscoped** — cynative uses their base credentials directly. They are gated solely by the client-side host-pinning and action-authorization checks; there is no AWS-side credential backstop for those identities. Cynative no longer mints `GetFederationToken` sessions, which could not call IAM APIs and so defeated IAM auditing.

The active mode is shown in the startup connector inventory as `sts=<mode>` (see [Reading the posture](#reading-the-posture)) so operators can confirm whether the AWS-side boundary is in force for their identity.

### Host pinning

Cynative maps AWS request hosts to an AWS service and region before signing. It rejects unsupported hosts, IP literals, localhost, and VPC endpoints, and the request host must match the model-supplied `aws_auth.service` and `aws_auth.region`.

This keeps a model-authored request from claiming one AWS target while sending credentials to another.

### Action authorization

Before signing the request, Cynative classifies the AWS operation, resolves the IAM action or actions required for it, and checks them against the configured policy with `iam:SimulateCustomPolicy`. That simulation API must be available to the launching credentials; if it is denied, the gate fails closed.

The resolver uses three sources in order: AWS Service Reference API, iam-dataset, then `namespace:op` derivation. The gate fails closed: if Cynative cannot resolve a required action, the request is denied.

One operation requires no IAM permission and is needed often enough to pin: `sts:GetCallerIdentity` (the "who am I" call, which AWS documents as requiring no permissions). Cynative recognizes it from a built-in list and allows it without policy simulation, so it stays available even when the iam-dataset is unavailable. Other no-permission operations are deliberately not pinned: `sts:GetSessionToken` issues credentials, and `dynamodb:DescribeEndpoints` is not needed by any Cynative workflow — both must clear the configured policy like any other action, and a read-only policy denies them. The fail-closed guarantee for every other operation is unchanged: an action Cynative cannot resolve is denied.

Hardening metadata, including service models and action registries, is cached under the shared `cache.dir`. The TTL controls whether a new process or cache object reuses disk data or fetches fresh data; after a successful load, a running process keeps its in-memory copy for the rest of that session.

### Response redaction

Cynative redacts secret-shaped content and credential-named fields from responses before the model sees them. The default `SecurityAudit` policy also avoids direct secret-value APIs such as `secretsmanager:GetSecretValue`, `kms:Decrypt`, `ssm:GetParameter`, and `ec2:GetPasswordData`.

Redaction is a defense-in-depth layer, not a reason to treat returned AWS data as public. See the limitations below for the exact caveats.

### Reading the posture

The AWS connector line in the startup connector inventory shows two terms:

```text
policy=arn:aws:iam::aws:policy/SecurityAudit · sts=disabled
```

`policy=` is the configured IAM policy the action gate and (when active) the STS scope enforce.

`sts=` is the credential-downscoping status resolved eagerly at startup, with these values:

- `assume_role` — STS `AssumeRole` scoping is active; the agent runs with a time-limited role-session scoped to the configured policy.
- `assume_role (unverified)` — the eager STS probe could not confirm the scope (for example a transient STS error); the real scope resolves on the first request, and the logged mode is a best-effort estimate. If that request-time resolution degrades to unscoped, Cynative emits a one-line `⚠️ aws_hardening: cred_scope degraded to disabled (reason=…) — requests now run with full base AWS credentials …` warning to stderr — the only runtime signal for that lazy degrade.
- `disabled` — no credential scoping; applies to IAM-user and root identities by design. The host-pinning and action-authorization gates remain in force; there is no AWS-side credential backstop.
- `disabled (degraded: <reason>)` — the eager startup probe attempted scoping for an assumed-role identity and was denied (for example `assume_role_unavailable`); the session falls back to the base, unscoped credentials and only the host-pinning and action-authorization gates are in force. This column value is the signal — no separate stderr diagnostic is emitted for a degrade detected at startup.

If hardening initialization fails at first use (for example the IAM policy cannot be fetched), the request is denied with an `aws_hardening: not_ready: …` error returned to the model, and the failure is cached for the rest of the session. (Credential or identity problems that prevent the connector from registering surface at startup as `aws_hardening: skipped …` instead.)

### How this compares to read-only MCP servers

The AWS Labs [AWS API MCP Server](https://github.com/awslabs/mcp/tree/main/src/aws-api-mcp-server) offers a `READ_OPERATIONS_ONLY` mode. It is useful, but it sits at a different trust boundary than Cynative's default AWS posture.

| Dimension | Cynative AWS connector | AWS API MCP Server `READ_OPERATIONS_ONLY` |
|---|---|---|
| Enforcement boundary | Client-side host and action gates always; AWS-side scoped credentials for assumed-role identities only | Client-side operation allowlist inside the MCP server |
| Credentials used for AWS calls | STS session scoped by the configured policy for assumed-role identities; IAM-user and root use base credentials (no AWS-side scoping) | The launching user's ambient AWS credentials, unchanged |
| Default posture | Hardening is on by default with `SecurityAudit` | `READ_OPERATIONS_ONLY` defaults to off |
| Read decision | Required IAM actions must be allowed by the configured policy | Operation is classified as read-only by service metadata and allowlists |
| Backstop if classification is incomplete | For assumed-role identities with a read-only policy, AWS IAM normally denies mutating actions even if the client-side gate misses them; IAM-user and root have no AWS-side credential backstop | No AWS-side backstop unless the operator separately restricts IAM |

The practical difference is that Cynative can put an AWS IAM boundary under an assumed-role agent, not just a local read filter in front of it. The MCP mode is still a valuable guardrail, especially when paired with least-privilege IAM, but it is not the same as issuing the agent a scoped credential.

### Why Cynative uses policy simulation

A raw read/write classifier asks whether an operation is read-only. Cynative asks a different question: does the configured IAM policy allow the IAM actions required by this operation?

That matters because `SecurityAudit` is not simply "all read actions." It is an AWS-maintained policy for security auditors. For example, `secretsmanager:GetSecretValue` is an IAM Read action, so a pure read/write classifier can allow it. `SecurityAudit` does not grant it, so Cynative blocks it by default.

A stricter configured policy tightens the client-side gate and, for assumed-role identities, the STS credential scope. That keeps the documented policy and the credential boundary aligned.

> Third-party behavior described above was checked against the AWS Labs MCP repository and AWS documentation in June 2026. These servers change quickly, so re-check before relying on this comparison.

### Choosing your exposure level

Cynative ships a curated read-only baseline — `SecurityAudit` — that you can re-point to a different managed or customer IAM policy via `connectors.aws.policy`. This is a spectrum of exposure, not a binary read/write toggle.

On AWS the chosen policy is enforced as the client-side action gate for all identities. For assumed-role identities it is also enforced as the STS session scope — a double boundary that keeps the documented policy and the credential boundary aligned. IAM-user and root requests are gated solely client-side (host pinning + action gate); there is no AWS-side credential backstop for those identities.

## Cynative configuration

### Exposure & authorization settings

The IAM policy the action gate enforces (for all identities), and — for assumed-role identities — the STS session scope. Default `arn:aws:iam::aws:policy/SecurityAudit`; see [Hardening](#hardening) for how it is applied.

```yaml
connectors:
  aws:
    policy: arn:aws:iam::aws:policy/SecurityAudit
```

```bash
export CYNATIVE_CONNECTORS_AWS_POLICY=arn:aws:iam::aws:policy/SecurityAudit
```

### Cache settings

AWS hardening metadata (service models and action registries) is cached under `<cache.dir>/aws`. The cache is shared across connectors — see [Shared configuration](README.md#shared-configuration).

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

- Credential downscoping (assumed-role identities) is best effort. An unrecognized caller ARN renders `sts=disabled (degraded: unrecognized_arn)`; an assumed-role self-assumption denial degrades to `sts=disabled (degraded: assume_role_unavailable)`. Invalid or unfetchable policy documents are hard failures. IAM-user and root identities show `sts=disabled` by design — they run unscoped, gated solely by host pinning and the action gate.
- Cynative no longer mints `GetFederationToken` sessions. A **federated-user caller's own base credentials** are already a `GetFederationToken` session that cannot call IAM APIs. Hardening initialization fetches the configured IAM policy document through IAM APIs; because that session cannot call those APIs, Cynative fails initialization for federated-user callers instead of continuing in disabled mode. Switch to an IAM-user or assumed-role identity to use the AWS connector.
- The assumed-role path re-assumes the underlying role with Cynative's configured `PolicyArns`; it does not inherit a session policy that may already narrow the current shell session. A heavily session-scoped caller can therefore get broader read access than its current session, though still capped by the configured policy.
- The AWS-side read-only backstop depends on `connectors.aws.policy` being read-only and applies **only to assumed-role identities**. For IAM-user and root, the action-authorization gate is the sole control; there is no AWS-side credential backstop. If you configure a managed policy that grants mutating actions, both the STS scope (for assumed-role) and the action-authorization gate follow that policy.
- Session policies are not an absolute ceiling against every resource-based policy. For example, an S3 bucket or KMS key policy that grants directly to the STS session principal can bypass the session policy boundary ([IAM session policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session)).
- `SecurityAudit` is read-oriented, not strictly side-effect-free. It includes a few audit-support actions with benign side effects, such as `iam:GenerateCredentialReport` and `config:DeliverConfigSnapshot` ([SecurityAudit managed policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)).
- Action authorization requires the launching credentials to call `iam:SimulateCustomPolicy`. Credentials that can read the configured policy but cannot simulate it can initialize hardening, then fail requests that require policy evaluation.
- Action authorization simulates **action names** against the configured policy; it does not pass per-request resource ARNs or condition context (the resource defaults to `*`). The simulation is therefore exact only for action-level policies with `Resource: *`, such as the default `SecurityAudit`. For a configured policy whose read-only intent depends on resource scoping, conditions, or explicit `Deny` on specific resources, enforcement differs by identity:
  - **Assumed-role** identities still have that intent enforced AWS-side by their scoped credential.
  - **IAM-user and root** identities run unscoped (see [Credential scoping](#credential-scoping-aws-side)), so the configured policy is enforced only as far as the action name: a resource-scoped *allow* is denied conservatively, but a broad *allow* with an explicit *deny* on a specific resource is **not** blocked for that resource. Prefer an action-level read-only policy (like the default), or an assumed-role identity, when you need resource- or condition-level enforcement. Resource-aware simulation is tracked as a future enhancement.
- The configured IAM policy document is fetched live during hardening initialization with `iam:GetPolicy` and `iam:GetPolicyVersion`; it is not cached under `cache.dir`.
- Model-supplied credential rejection checks credential headers and URL userinfo. It does not parse SigV4 query parameters such as `X-Amz-Signature`, `X-Amz-Credential`, or `X-Amz-Security-Token` on presigned URLs.
- Response redaction is pattern-based and best effort. It targets secret-shaped tokens and credential-named fields, not arbitrary sensitive values. The `Location` response header is intentionally passed through so the agent can follow redirects, including signed URL redirects.
- The default `SecurityAudit` policy can still return sensitive data through non-secret APIs, such as Lambda environment variables from `lambda:GetFunctionConfiguration` or S3 Vectors data from `s3vectors:GetVectors` when `returnData` is set. Treat returned AWS data as sensitive.
- VPC endpoints and IP-literal AWS targets are rejected by host hardening.
- The AWS connector covers AWS service APIs; for Kubernetes API calls to EKS clusters, see the [eks connector](eks.md).
