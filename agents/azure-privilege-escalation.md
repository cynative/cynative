---
description: Map the Azure principals that can grant themselves further access, and report the scope each one holds it at.
---

Research which principals hold a role permitting `Microsoft.Authorization/roleAssignments/write` in this tenant, and at what scope each holds it.

List every role definition whose `actions` grant the assignment-write action and whose `notActions` do not remove it, resolving wildcards rather than matching the literal string - Owner carries it as `*`, User Access Administrator as `Microsoft.Authorization/*`, Role Based Access Control Administrator in full, and a custom definition either way, while Contributor carries `*` but removes it with `Microsoft.Authorization/*/Write` - then list the assignments of those roles with the scope and `principalType` of each, taking the scopes you enumerate from the tenant's own management group and subscription listings rather than from the subscription the credential defaults to, since an assignment made at a management group or at a sibling subscription appears in neither, read the deny assignments in force at those scopes, and read which Function app managed identities are assigned Owner, Contributor, User Access Administrator or Role Based Access Control Administrator.

A deployment service principal or a pipeline connection holding an assignment-write role is present in nearly every tenant, so its existence settles nothing. What distinguishes them is scope: an identity assigned at a single resource group is bounded by that resource group, and the same identity at subscription or management group scope is not.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every assignment-write holder is either assigned at resource group scope or narrower or bounded at its scope by a deny assignment removing the assignment-write action, and no custom role definition carries that action. Report the holder inventory with each assignment's scope and `principalType`, each role definition's `actions` and `notActions` entries carrying the assignment-write action, the deny assignments in force at those scopes, the Function app managed identities assigned Owner, Contributor, User Access Administrator or Role Based Access Control Administrator, and the count of management groups and subscriptions the enumeration covered, and which of the assignment, role definition and deny assignment enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the holders that are not clean:

Report service principals and app identities first, with their assignment scope, since scope is the only thing bounding a non-interactive identity. For Function app identities, report the app's public network access setting alongside.

Report custom roles containing the assignment-write action at subscription scope as Owner-equivalent, naming the `actions` entry that carries it.

For each holder above resource group scope, report what the scope contains: the subscriptions under a management group assignment, or the resource groups under a subscription assignment. An assignment inherits down every level below it, so the scope is what the holder can grant over.

Report an assignment-write holder as intentional where the evidence supports it: a deny assignment at the same scope removing the assignment-write action from that principal, a custom role definition whose `assignableScopes` names one resource group, or a Function app managed identity assigned at the resource group its own app sits in. Name the evidence. A holder at subscription or management group scope with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Role definitions: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions` on `management.azure.com`; one definition at `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{roleDefinitionId}`, and the tenant-wide set at `GET /providers/Microsoft.Authorization/roleDefinitions`.

Role assignments: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments` on `management.azure.com`; one group's assignments at `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/roleAssignments`.

Deny assignments: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/denyAssignments` on `management.azure.com`; one group's at `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/denyAssignments`.

Tenants and subscriptions: `GET /tenants` and `GET /subscriptions` on `management.azure.com`; the group listing at `GET /subscriptions/{subscriptionId}/resourcegroups`.
