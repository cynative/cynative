# Threat Model

## Design intent

Cynative is designed so that it does not modify the infrastructure it
inspects and cannot widen its own access, whatever the model does. The
controls below are how that is enforced.

## Adversary

The model is untrusted. Prompts, tool results and API responses are all
attacker-influenceable. The adversary's goals: induce a write, reach a
host outside the target infrastructure, exfiltrate credentials, escape
the sandbox.

Out of scope: a malicious operator, a compromised host, and the
credentials the operator supplies.

## Trust boundaries

1. **Model to agent** - every tool call crosses the action gate.
2. **Sandbox to host** - scripts get the exposed tools only. No network,
   filesystem or packages.
3. **Agent to provider** - credentials attach only after the gate
   authorizes and the host and resolved IP are verified.
The model never holds credentials and never chooses the policy, so it
cannot move any of these lines.

## Controls

- **Least privilege** - SecurityAudit, roles/viewer, Reader, live view
  RBAC. For AWS assumed-role identities, credentials are re-vended
  through STS scoped to a managed policy, so IAM enforces the boundary
  independently.
- **Fail closed** - anything not classified as a read is denied.
- **Complete mediation** - authorization is per request, not per session.
- **Defense in depth** - action gate, host pinning, provider-side IAM.

## Weaknesses countered

- **Command injection** - model output never reaches a shell or the host
  process; scripts run in the JS sandbox.
- **Request redirection** - hosts pinned, resolved IP verified before
  connect.
- **Repository-supplied prompts** - agents are read only from
  `~/.cynative/agents/` and the binary, never from the working directory.
  Selection is always explicit by name and the model never chooses an
  agent. Every audited tool call records the agent's name, source and file
  digest.
- **Credential leakage** - no credential store; secrets are redacted from
  tool results and the audit log, which is readable only by the running
  user.
- **Memory and concurrency bugs** - pure Go, no cgo; the full test suite
  runs under Go's race detector.
- **Untested paths** - 100% statement coverage enforced in CI.
- **Dependency compromise** - versions pinned in go.mod, Dependabot
  updates, CodeQL and gosec on every PR.
- **Artifact tampering** - releases carry checksums signed with cosign
  keyless and GitHub build attestations, verified by install.sh.

---

This describes design intent and implemented controls, not a warranty.
See [LICENSE](https://github.com/cynative/cynative/blob/main/LICENSE).
