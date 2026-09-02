---
description: Determine the shortest path to each Azure Key Vault's contents, whether the read would be recorded and whether the vault can be purged.
---

Research which Key Vaults in this subscription can be reached and read, whether that read would be recorded and which vaults can be permanently destroyed.

Read each vault's permission model, `publicNetworkAccess`, network ACL default action, IP rules and virtual network rules, private endpoint connections, soft delete state, purge protection state, and whether a diagnostic setting with the `AuditEvent` category has a destination.

Soft delete and purge protection are two settings and describe two different outcomes: soft delete decides whether a deleted secret can be recovered at all, purge protection decides whether the recovery window can itself be cancelled. Read both and report both.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every vault uses Azure RBAC, has soft delete and purge protection enabled, and has a diagnostic setting carrying the `AuditEvent` category to a destination. `publicNetworkAccess` and the network ACL default action both ship open and stay open on every vault anything outside a private endpoint reaches, so they describe reachability rather than access and are reported below rather than tested here. Report the vault inventory with the permission model, the soft delete and purge protection state, the `publicNetworkAccess` value, the network ACL default action, IP rules and virtual network rules, and the private endpoint connections per vault, and which of the vault and diagnostic setting reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the vaults that are not clean:

For vaults on the legacy access policy model, report each access policy entry with its object ID and the secret permissions it holds. Access policy entries are scoped to the whole vault rather than to individual secrets, so an entry carrying a secret permission carries it on every secret the vault holds.

For vaults on the Azure RBAC model, report each role assignment scoped at the vault, at an individual secret, key or certificate within it, or inherited from above the vault, that grants a data-plane role over secrets or keys, such as Key Vault Secrets User, Key Vault Secrets Officer or Key Vault Administrator, naming the principal, the role, the scope it was assigned at and any deny assignment or assignment condition bounding it. A role assigned at the subscription or resource group reaches every vault beneath it, not only the one under review.

Report the network configuration as a combination rather than a single field, since a private endpoint does not disable public access on its own.

Where purge protection is disabled, resolve which role definitions include `Microsoft.KeyVault/locations/deletedVaults/purge/action` and which principals hold them, and report the disk encryption sets, storage accounts and other resources referencing keys in the vault. Where soft delete is also off, report that the deletion is immediate and unrecoverable rather than delayed.

Report a vault reachable from the internet as intentional where the evidence supports it: a network ACL whose IP rules name addresses another resource in this subscription also holds, or a vault whose only consumers are outside the virtual network and are named in its access policy or role assignments. Name the evidence. A vault open to the internet with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Key Vaults: `GET /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults` on `management.azure.com`; one vault's own settings at `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}`, and the soft-deleted set at `GET /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/deletedVaults`.

Diagnostic settings on a vault: `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/providers/Microsoft.Insights/diagnosticSettings` on `management.azure.com`.

Role assignments and definitions: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments` and `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions`, on `management.azure.com`; a vault's own assignments at `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/providers/Microsoft.Authorization/roleAssignments`.

Resource Graph: `POST /providers/Microsoft.ResourceGraph/resources` on `management.azure.com`.

Subscriptions and their contents: `GET /subscriptions` on `management.azure.com`; the resource inventory at `GET /subscriptions/{subscriptionId}/resources`.
