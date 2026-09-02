---
description: Determine who can reach a self-managed Kubernetes cluster's API server, as which identity and what its admission chain accepts.
---

Research how this cluster's API server authenticates and authorizes requests, and what its admission chain accepts. Every argument below is read from the API server's own pod, so this agent applies to a self-managed control plane only: where a pod enumeration that answered returns no such pod, this cluster does not run its API server as a pod, whether the control plane is provider-managed or self-managed and runs the API server as a host process, and the answer is that this agent does not apply rather than a page of unresolved arguments. An enumeration that failed is not that answer and settles nothing: report it as unresolved rather than as an absent control plane. The etcd arguments and the kubelet arguments are outside this agent's scope.

Read the API server's effective arguments from its static pod manifest or its running pod specification: `--authorization-mode`, `--enable-admission-plugins` and `--disable-admission-plugins`, `--anonymous-auth`, `--client-ca-file`, `--token-auth-file`, `--service-account-key-file`, `--service-account-lookup`, `--tls-cert-file`, `--tls-private-key-file` and `--audit-log-path`.

An argument the command does not carry is not unread: the API server takes the binary's documented default for that version, so resolve the effective value and report the argument as defaulted rather than as configured or as missing. `--anonymous-auth` and `--service-account-lookup` both default to true, so an absent `--anonymous-auth` is anonymous authentication in force and an absent `--service-account-lookup` is the same state as `--service-account-lookup=true`. An absent `--token-auth-file` is the intended state and not a finding; an absent `--audit-log-path` is a finding, and the difference is which absence leaves a control off.

`--enable-admission-plugins` names plugins enabled in addition to a default set, so a plugin absent from it is not absent from the chain: it runs unless `--disable-admission-plugins` names it. `NamespaceLifecycle`, `ServiceAccount` and `PodSecurity` are in that default set, so absence from the enable list says nothing about them and only the disable list turns them off. `NodeRestriction` and `DenyServiceExternalIPs` are not in it, so for those two the enable list is the whole answer. Resolve each plugin to in force or not in force from the two lists together.

Where `--authorization-mode` contains `AlwaysAllow`, report that as the single finding and end: the authorizer admits every caller to everything regardless of identity, so every other argument bounds a caller that is no longer bounded, and reporting them would describe protections that do not run.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if `--authorization-mode` includes both `RBAC` and `Node`, `--anonymous-auth` is false, no `--token-auth-file` is configured, `--service-account-lookup` is true, `--client-ca-file`, `--service-account-key-file`, `--tls-cert-file` and `--tls-private-key-file` are all set, `--audit-log-path` is set and the admission plugins do not contain `AlwaysAdmit`. Report the argument inventory, the `--enable-admission-plugins` and `--disable-admission-plugins` lists with whether each of `NodeRestriction`, `ServiceAccount`, `NamespaceLifecycle`, `DenyServiceExternalIPs`, `PodSecurity` and `SecurityContextDeny` is in force, and the `--audit-log-path` value, and end.

Only for the arguments that are not clean:

Where anonymous authentication is enabled, report it against `--authorization-mode`: the setting admits an unauthenticated caller as `system:anonymous` in the `system:unauthenticated` group, and what that caller then reaches is whatever the authorizer grants those two subjects. Report the pair as the finding and say that the bindings themselves are outside what this agent reads.

Report `--token-auth-file` as set with its contents unread - the file sits on the control plane node and no call through the API server returns it - since the argument being present is itself the finding: static tokens cannot be revoked without restarting the API server. Report `--service-account-lookup=false` as a persistence property, since tokens stay valid after the token object is deleted.

Where the admission plugins contain `AlwaysAdmit`, report that as its own finding: it runs as its own step in the chain and never denies what it is asked, but it does not run in place of the other admission plugins or override their denials, so the plugins named above still enforce their own checks. Name the plugins from the list above that are not in force and state what each absence permits. `NodeRestriction` absent permits a node credential to modify other nodes' `Node` and `Pod` objects rather than only its own, so report it with the number of distinct nodes the pod specifications name, resolved from those specifications rather than from the node object, which is where node identity is reachable from. `PodSecurity` is the admission plugin that enforces the pod security standards and is one of the three above that the default set carries, so it is a finding only where `--disable-admission-plugins` names it; `PodSecurityPolicy` and `SecurityContextDeny` have both since been removed from Kubernetes, so report which of the three the cluster's own version still recognises rather than reporting all three as equivalent. `DenyServiceExternalIPs` ships out of the enabled set in every distribution, so its absence is the default rather than a decision and reporting it alone says only that the cluster is stock: report it against whether any Service in this cluster sets `spec.externalIPs`, since what the plugin bounds is a subject that can create or update one.

Report missing authentication and TLS arguments with the distribution and version, since defaults differ between them, then report `--audit-log-path` unset alongside rather than on its own.

Report an admission plugin that is not in force as intentional where the evidence supports it: a policy controller running as a Deployment in this cluster whose own pods you can name - the Deployment and its pods are the evidence, rather than the webhook configuration it registers - or a `pod-security.kubernetes.io/enforce` label on the namespaces the plugin would have covered. Name the evidence. A plugin not in force with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Kubernetes API: `GET /api/v1/namespaces/kube-system/pods` for the control plane's own pods, and `GET /api/v1/pods`, `GET /api/v1/namespaces`, `GET /api/v1/services` and `GET /apis/apps/v1/deployments`; the server version at `GET /version`.
