---
description: Determine which pods reach their node, what that node holds and which pod specifications carry literal secret values.
---

Research which pods in this cluster can reach their node, and which pod specifications carry secret values in plaintext.

Scan every pod's containers, init containers and ephemeral containers for the fields that cross the node boundary - `privileged`, `SYS_ADMIN` in added capabilities, `hostPath` volume mounts taking the host path from the volume and the read-only flag from the mount that references it, and Windows `hostProcess` - read `hostPID`, `hostIPC` and `hostNetwork` once from the PodSpec, since none of the three exists on an individual container, and apply each to every container in that pod - for `hostPort`, which exposes the container on the node's network interface without crossing that boundary itself - and for environment variables carrying a literal value rather than a `secretKeyRef`, and for `command` and `args` entries on those same containers. Select on the variable rather than on every literal: a name containing `PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `CREDENTIAL` or `PASSPHRASE` - a variable name for an environment variable, a flag name for a `command` or `args` entry - or a value that is a private key block, a bearer token or a connection string carrying a password. The bound is there because a pod specification is mostly literal configuration, so an unbounded scan returns the cluster's environment rather than its secrets.

Read each pod's `ownerReferences` and its `kubernetes.io/config.source` annotation: a pod whose annotation holds `file` and whose `ownerReferences` name the node rather than a controller is a static pod, which the kubelet started from a manifest on that node and is how a self-managed control plane runs its own components.

Read `automountServiceAccountToken` on each pod and on the service account it runs as, together with the service account name. A pod that reaches its node holds whatever the node holds, but it also holds its own mounted token, and whether that token is mounted at all is the difference between a container escape reaching the API server as that service account and reaching it as nothing.

Read the counts per namespace, over those same containers, of the ones that permit privilege escalation by setting `allowPrivilegeEscalation` true or leaving it unset, that add any capability, that retain `NET_RAW` by not dropping it, that do not drop `ALL`, that do not block root execution because `runAsNonRoot` is false or unset and `runAsUser` is 0 or unset at both pod and container level, and that carry no `RuntimeDefault` seccomp profile at either level, in the same pass.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if the only containers setting `privileged`, `SYS_ADMIN`, `hostPath`, `hostPID`, `hostIPC`, `hostNetwork`, `hostPort` or `hostProcess` belong to DaemonSets from a CNI, CSI or monitoring component or to the static pods named above, and no container carries a literal value in place of a `secretKeyRef` in one of the environment variables named above, and no `command` or `args` entry on those containers carries a value matching that same bound. A static pod crosses that boundary by construction, so its boundary fields say nothing that is not true of every cluster of its kind. Report each of those DaemonSets and static pods with its image reference, its namespace, whether it sets `privileged` or adds `SYS_ADMIN`, and `hostPID`, `hostIPC`, `hostNetwork` or `hostProcess`, and the host path and read-only flag on each `hostPath` mount it carries, the `automountServiceAccountToken` state per namespace with the service account name each pod runs as, and the counts per namespace for `allowPrivilegeEscalation` true or unset, added capabilities, `NET_RAW` retained, capability drops missing `ALL`, root execution not blocked by `runAsNonRoot` and `runAsUser`, and missing `RuntimeDefault` seccomp profiles, and end.

Only for the pods that are not clean:

For each pod reaching the node, report the service accounts mounted on that node's other pods and what else is scheduled there, resolved from the node name each pod specification already carries rather than from the node object. A `hostPath` mount of `/`, `/var/lib/kubelet`, `/etc/kubernetes`, a node certificate directory, or the container runtime socket - `/run/containerd/containerd.sock` on a current cluster and `/var/run/docker.sock` on one still running Docker - is the node; report the path and the read-only state.

Report `hostPort` as inbound exposure on the node's network interface rather than as a pod reaching the node: it does not carry the container's access to the node's filesystem, processes or credentials with it. Name the port, the pod and the namespace.

Report `hostNetwork` with what it reaches on that node - the kubelet port and any loopback-bound node service - and `hostPID` and `hostIPC` with the processes and memory of the other containers on the host.

Report literal environment values and literal `command` or `args` values with the variable or flag name, the pods and the namespaces: they are readable by any subject that can read the pod specification.

Name each pod's service account within the `automountServiceAccountToken` state above, and report the pods that both reach the node and mount a token as the compounding case: the escape carries an API server identity out with it rather than stopping at the node.

Name only the containers already reported above within the hardening counts.

Report a static pod's node-boundary fields as an inventory of the control plane rather than as findings - the pod, the component it runs and the directory it mounts - and place that inventory below the findings. The same directory mounted by anything that is not that component is a finding.

Report a `hostPath` mount as intentional where the evidence supports it: a read-only mount confined to a log directory or a CA bundle, a socket or state directory that a CSI or CNI DaemonSet in this cluster owns and that the mounting pod is part of, or a control-plane directory mounted by the static pod of the component that owns it. Name the evidence. A `hostPath` mount reaching a node path with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Kubernetes API: `GET /api/v1/pods` and `GET /api/v1/serviceaccounts`; the namespace listing at `GET /api/v1/namespaces`; workload controllers at `GET /apis/apps/v1/daemonsets`, `GET /apis/apps/v1/deployments`, `GET /apis/apps/v1/replicasets` and `GET /apis/apps/v1/statefulsets`.
