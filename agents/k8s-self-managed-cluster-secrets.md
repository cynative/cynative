---
description: Determine what can read a self-managed Kubernetes cluster's etcd directly, and whether an encryption provider is configured for the secrets in it.
---

Research what can read this cluster's etcd without passing through RBAC or the audit log, and whether an encryption provider is configured for the secrets stored there. Every argument below is read from the etcd and API server pods, so this agent applies to a self-managed control plane only: where a pod enumeration that answered returns no such pods, the control plane is provider-managed and runs both outside the cluster, and the answer is that this agent does not apply rather than a page of unresolved arguments. An enumeration that failed is not that answer and settles nothing: report it as unresolved rather than as an absent control plane. The API server's authorization and admission arguments and the kubelet arguments are outside this agent's scope.

Read the etcd pod's `--client-cert-auth`, `--auto-tls`, `--peer-client-cert-auth`, `--peer-auto-tls`, `--listen-client-urls`, `--listen-peer-urls`, `--cert-file`, `--key-file`, `--peer-cert-file`, `--peer-key-file` and `--trusted-ca-file`, and the API server's `--etcd-cafile`, `--etcd-certfile`, `--etcd-keyfile`, `--client-ca-file` and `--encryption-provider-config`.

An argument the command does not carry is not unread: etcd takes its own documented default for that version, so resolve the effective value and report the argument as defaulted rather than as configured or as missing. `--auto-tls` and `--peer-auto-tls` default to false, so their absence is the intended state. `--client-cert-auth` and `--peer-client-cert-auth` also default to false, so their absence is certificate authentication off rather than a gap in the read, and it is the same finding as the argument present and false.

`--encryption-provider-config` names a path on the control plane node, and the manifest carries the path rather than the contents. `EncryptionConfiguration` belongs to `apiserver.config.k8s.io`, a component configuration group the API server parses from disk and does not serve, so no call reaches the file and its providers stay unknown whatever the cluster role grants.

The argument being set is therefore not encryption. The file lists providers in order and the first one for a resource encrypts new writes, `identity` is the no-op provider, and a configuration listing `identity` first for `secrets` writes them in plaintext while still satisfying a check that only asks whether the argument is set. Report a configured argument as unverified rather than as encryption in force, and report an absent one as no encryption at all, which is the one state the manifest settles.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if `--client-cert-auth` and `--peer-client-cert-auth` are both true with `--auto-tls` and `--peer-auto-tls` both false, its `--trusted-ca-file` differs from the API server's `--client-ca-file`, the API server presents `--etcd-certfile` and `--etcd-keyfile` with an `--etcd-cafile`, and `--encryption-provider-config` is set. Report the argument inventory with the `--listen-client-urls`, `--listen-peer-urls`, `--cert-file`, `--key-file`, `--peer-cert-file` and `--peer-key-file` values, the `--trusted-ca-file` and `--client-ca-file` paths as compared by path only with whether they name the same underlying certificate authority left unread, and the `--encryption-provider-config` path with its providers marked unread, and end.

Only for the settings that are not clean:

Report `--client-cert-auth=false` or `--auto-tls` with the interface etcd listens on, the pods scheduled to the control plane nodes and whether any uses `hostNetwork`. Report the peer-port equivalents the same way.

Where etcd's trust anchor is the same authority as the API server's client CA, report it with the number of distinct nodes the pod specifications name, resolved from those specifications rather than from the node object, which is where node identity is reachable from: any certificate that authority issued authenticates to etcd, including the kubelet client certificates every node holds and any certificate issued through the CSR API.

Where `--encryption-provider-config` is absent, report the cluster's secrets as stored in plaintext in etcd - a cluster-level fact that needs no read of the secrets themselves - and report it against the etcd exposure above rather than on its own: the two findings compound, since an unauthenticated etcd holding plaintext secrets is one read away from every credential the cluster holds.

Report an absent encryption provider configuration as intentional where the evidence supports it: a secrets operator running as a Deployment in this cluster whose own pods you can name and that supplies credentials from a store outside etcd, or workload pods that take their credentials from a `csi` volume naming such a provider rather than from a `secret` volume. Name the evidence. An API server running as a pod in this cluster and setting no `--encryption-provider-config` with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Kubernetes API: `GET /api/v1/namespaces/kube-system/pods` for the control plane's own pods, and `GET /api/v1/pods` and `GET /apis/apps/v1/deployments`.
