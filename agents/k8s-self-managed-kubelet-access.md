---
description: Determine whether a kubelet in a self-managed Kubernetes cluster can be reached directly and what it requires before executing in a pod.
---

Research whether a kubelet in this cluster can be reached directly on its own API, which executes in any pod on that node and what it requires first. The kubelet settings come from the ConfigMap kubeadm publishes them in and the API server's arguments from its own pod, so this agent applies to a self-managed control plane only: where reads that answered return neither, this cluster does not publish its kubelet configuration through kubeadm's ConfigMap, whether the control plane is provider-managed or self-managed and configures kubelets another way, and the answer is that this agent does not apply rather than a page of unresolved settings. A read that failed is not that answer and settles nothing: report it as unresolved rather than as this agent not applying.

Read the kubelet configuration's `authentication.anonymous.enabled`, `authorization.mode`, `authentication.x509.clientCAFile`, `tlsCertFile`, `tlsPrivateKeyFile`, `rotateCertificates` and `readOnlyPort`, and the API server's `--kubelet-certificate-authority`, `--kubelet-client-certificate` and `--kubelet-client-key`.

`readOnlyPort` is a second listener. Where it holds anything other than 0, the port it names serves pod and node state with no authentication and no authorization at all, so it is a separate reachability question from the authenticated port 10250 and is read and reported as its own field. Report the number the field holds rather than assuming it: the field takes any port from 1 to 65535, 10255 is only the conventional choice, and its own default is 0, which is the effective value where the configuration does not carry the field.

Take the kubelet settings from the `kubelet-config` ConfigMap in `kube-system`, which is where kubeadm publishes the configuration the nodes start from. It carries the cluster-wide defaults and no per-node override, so report a value as the cluster default rather than as that node's effective setting. A setting it does not carry and the kubelet documents a default for takes that default, reported as the cluster default rather than as a configured value. `tlsCertFile` and `tlsPrivateKeyFile` are the other case: kubeadm writes neither, a kubelet given neither generates and serves a certificate it signed itself, and a per-node flag could set either without appearing here - so report them as unresolved and say which of those two states the ConfigMap cannot tell apart. Take the node names from the pod specifications rather than from the node object.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if the cluster-wide kubelet configuration sets `Webhook` authorization with `authentication.anonymous.enabled` false, `authentication.x509.clientCAFile` set, `rotateCertificates` true and `readOnlyPort` either 0 or absent, and the API server has `--kubelet-certificate-authority`, `--kubelet-client-certificate` and `--kubelet-client-key` set. Report the cluster-wide `authorization.mode`, `readOnlyPort` value and `rotateCertificates` state once, whether the ConfigMap carries `tlsCertFile` and `tlsPrivateKeyFile`, and the node names the pod specifications carry, and end.

Only for the kubelets that are not clean:

Report `authorization.mode: AlwaysAllow` on its own, since it authorizes any authenticated caller regardless of `authentication.anonymous.enabled`, and report `authentication.anonymous.enabled` true alongside it where both hold, then resolve whether any NetworkPolicy restricts pod traffic to node addresses - without one, nothing this agent reads restricts pod traffic to port 10250 on any node, though a host firewall, cloud security group or other node-level control it does not read could still narrow that. The ConfigMap carries one value for the whole cluster, so no node is affected in isolation: report the pods scheduled to each of the nodes the pod specifications name.

Report a non-zero `readOnlyPort` with the number the field holds and the pods scheduled to those same nodes, since the port it names returns their specifications and status to any caller that reaches a node address, and rank it above an authenticated port that a binding happens to expose.

Where `authorization.mode` is `Webhook`, the kubelet delegates each request to the API server's authorizer, so the port is reachable but every call is decided by whatever holds `nodes/proxy`. Report the mode as bounding rather than open, and say that the bindings that decide it are outside what this agent reads.

Report `--kubelet-certificate-authority` unset on the API server, which leaves kubelet certificates unverified, with the network the control plane and nodes share, and report `rotateCertificates` false against the nodes named above: the kubelet will not renew its client certificate on its own, and its actual lifetime is unresolved unless the certificate itself is read.

Report an unauthenticated kubelet listener as intentional where the evidence supports it: a `readOnlyPort` whose only consumer is a monitoring DaemonSet in this cluster whose pods you can name. A NetworkPolicy that names node addresses is not that evidence on its own, since whether a CNI enforces it against traffic to a node is outside what this agent reads. Name the evidence. An unauthenticated listener with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Kubernetes API: `GET /api/v1/namespaces/kube-system/pods` and `GET /api/v1/namespaces/kube-system/configmaps` for the control plane's own objects, and `GET /api/v1/pods`, `GET /apis/apps/v1/daemonsets` and `GET /apis/networking.k8s.io/v1/networkpolicies`; the API root at `GET /api`.
