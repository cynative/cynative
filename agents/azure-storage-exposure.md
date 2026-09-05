---
description: Resolve effective access to each Azure storage account across anonymous blob access, shared keys, the network rule set and Entra roles.
---

Research which storage accounts in this subscription hold data readable by an anonymous caller, by anyone holding an account key, or from the internet. Take which subscription that is from the credential's own subscription listing rather than from asking for it or from the identifier reported for the credential, which names the principal and not a subscription: the listing names the subscriptions the credential reaches, and where it names more than one, report each of them.

Read six settings per account: `allowBlobPublicAccess`, `allowSharedKeyAccess`, the network rule set's `defaultAction`, `publicNetworkAccess`, `supportsHttpsTrafficOnly` and `allowCrossTenantReplication`, together with the customer-managed key configuration. `publicNetworkAccess` set to `Disabled` blocks every request at the public endpoint and takes precedence over the network rule set - a `defaultAction` of `Allow` means the account answers from the internet only when `publicNetworkAccess` is `Enabled` or absent, and the virtual network and IP rules alongside `defaultAction` do not narrow that `Allow` - they are exceptions to a `Deny` default only.

A setting the account never set is absent from the body Resource Manager returns rather than present and empty, and an absent `publicNetworkAccess` is `Enabled`. A read that came back is a read that answered, so report the default as the value and say it was defaulted; a property missing from a body that arrived is not an unresolved read, and asking a second api-version for it returns the same body.

`allowSharedKeyAccess` is read but does not decide whether the expensive stage runs. Several Azure services still authenticate to storage with the account key, so an account with it enabled is the common case rather than the exceptional one, and gating on it would mean the expensive stage runs almost everywhere.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every account has `allowBlobPublicAccess` disabled, `supportsHttpsTrafficOnly` enabled and `allowCrossTenantReplication` disabled. That stop clears anonymous access to the blob endpoint and nothing else: an account with `allowSharedKeyAccess` enabled is readable by every holder of its key, and one whose `defaultAction` is `Allow` and `publicNetworkAccess` is not `Disabled` answers from the internet - so name the branch of the question that is clean rather than reporting the account as clean. The network rule set's `defaultAction` and `publicNetworkAccess` both ship open and stay open on every account anything reaches over the internet, so they describe reachability rather than access and are reported below for the same reason `allowSharedKeyAccess` is. Report the account inventory with the `allowSharedKeyAccess` state, the network rule set `defaultAction` and the `publicNetworkAccess` value per account, the customer-managed key state as a count, the accounts with a container named `$web` as a count, and the account receiving the subscription activity logs named with all six settings, and which of the account and activity log reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the accounts that are not clean:

Enumerate container public access levels from the account's `blobServices/default/containers` collection under Resource Manager, which carries each container's `publicAccess` value, and report the containers actually set to `Blob` or `Container`. `allowBlobPublicAccess` permits a container to be set public but does not make one public, so report the account-level flag separately as the condition that permitted it. Report the account's `publicNetworkAccess` value alongside a public container finding: one set to `Blob` or `Container` on an account with `publicNetworkAccess` `Disabled` is reachable only from inside the private endpoint's network, not the internet.

A container named `$web` survives disabling static website hosting along with everything already uploaded to it, so its presence alone does not establish that the web endpoint is still serving it - name the account and report the static website exposure unresolved rather than as currently anonymous, unless the container's own `publicAccess` is `Blob` or `Container`, which is a live and directly read fact.

Name the accounts from the shared key count above that also have an open network default and `publicNetworkAccess` not `Disabled`, and report those two together. An account key grants full control of every container, does not expire and attributes to no principal in the diagnostic logs.

Report `supportsHttpsTrafficOnly` disabled with the containers and file shares on the account, since an unencrypted request carries the shared access signature or account key that authorized it.

Where cross-tenant replication is enabled, report the object replication policies configured rather than the flag alone, and name each policy's `destinationAccount` - the policy itself records no tenant, and once cross-tenant replication is permitted the field need not be a full resource ID. Report any public access, open network default or enabled shared key on the account receiving subscription activity logs ahead of the others.

Name the accounts behind the customer-managed key count that still rely on a Microsoft-managed key.

Report a public container as intentional where the evidence supports it: a container named `$web`, which only static website hosting creates, or a CDN or Front Door origin in the subscription naming it. Name the evidence. A container set to `Blob` or `Container` with no such evidence is not intentional.


Order findings by risk, most consequential first.


Call shapes a run has proven:

Blob containers: `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/blobServices/default/containers` on `management.azure.com`.

Subscriptions: `GET /subscriptions` on `management.azure.com`.
