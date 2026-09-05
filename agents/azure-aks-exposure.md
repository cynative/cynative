---
description: Determine who can reach each AKS API server and which Azure principals can retrieve its static cluster-admin credential.
---

Research which AKS clusters in this subscription expose their API server, which permit a static cluster-admin credential to be retrieved, and which authorize without RBAC. Take which subscription that is from the credential's own subscription listing rather than from asking for it or from the identifier reported for the credential, which names the principal and not a subscription: the listing names the subscriptions the credential reaches, and where it names more than one, report each of them.

Read each cluster's API server access profile including `authorizedIPRanges`, `disableLocalAccounts`, `enableRBAC`, node pool `enableNodePublicIP`, and the Defender security profile state. A subscription that has never used AKS has not registered `Microsoft.ContainerService`, and a provider in that state holds none of its resource type rather than an unread one: take the registration state from `GET /subscriptions/{subscriptionId}/providers/{resourceProviderNamespace}`, which returns that provider's `registrationState` in a body that fits, and report it rather than reporting the enumeration as empty or as unresolved.

Take the authorized ranges as values, not as a verdict. Whether a given range covers a provider egress block or an entire corporate network is a judgment about what sits behind an address, which no field returns, so it is second-stage work; the condition below asks only whether a list exists and whether its entries, alone or together, cover the full IPv4 address space, which needs no such judgment: a list containing `0.0.0.0/0`, and a list whose entries add up to the same space without either one on its own, are the same fact.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every cluster has either a private API server or a non-empty `authorizedIPRanges` list whose entries do not, alone or together, cover the full IPv4 address space, has `disableLocalAccounts` set, has `enableRBAC` true and has no node pool with `enableNodePublicIP`. Report the cluster inventory with each cluster's `authorizedIPRanges` as read and the size of each range, the Defender security profile state as a count, and the registration state of the resource providers named above, and which of the cluster and provider reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the clusters that are not clean:

Report clusters with `enableRBAC` false ahead of everything else.

Where local accounts are enabled, resolve the principals holding `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action` - the action appears in the Azure Kubernetes Service Cluster Admin role and in Contributor at the resource group - and report that principal set as the finding. The credential it retrieves bypasses Entra authentication, Conditional Access and Kubernetes RBAC.

Judge the ranges reported above: a range covering a provider egress block or an entire corporate network admits everything behind it, and a cluster with no ranges at all admits the internet.

Report node pools with `enableNodePublicIP` together with the cluster's network plugin and network policy configuration, and name the affected clusters within the Defender security profile count.

Report an authorized range as intentional where the evidence supports it: a range matching a NAT gateway or firewall public address in this subscription, or a range no wider than the addresses a bastion or self-hosted runner in the subscription holds. Name the evidence. A range covering a whole corporate network or a provider egress block with no such evidence is not intentional.


Order findings by risk, most consequential first.


Call shapes a run has proven:

Resource provider registration state: `GET /subscriptions/{subscriptionId}/providers/{resourceProviderNamespace}` on `management.azure.com`.

Subscriptions: `GET /subscriptions` on `management.azure.com`.
