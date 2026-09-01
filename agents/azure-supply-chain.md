---
description: Determine who can push to each Azure container registry, which workloads pull from it and what the running images carry.
---

Research who can push images to the container registries in this subscription, which AKS, Container Apps and App Service workloads pull from them, and what the running images carry.

Read each registry's admin user state, `anonymousPullEnabled`, public network access and private endpoint connections. All of these come from Resource Manager. A subscription that has never used a container registry has not registered `Microsoft.ContainerRegistry`, and one that has never bought a Defender plan has not registered `Microsoft.Security`; a provider in that state holds none of its resource type rather than an unread one: take the registration state from the subscription's own provider listing, which returns every provider with its `registrationState`, rather than from a path naming one provider, and report it rather than reporting the enumeration as empty or as unresolved. An unregistered `Microsoft.Security` is the enablement state below answered rather than unread: the plan was never bought.

Read whether Defender for Containers vulnerability assessment is enabled for the subscription before reading the assessment count, and keep the two apart. A subscription with scanning switched off reports zero unresolved assessments, which is indistinguishable from a clean one unless the enablement state is read first, so the enablement state and not the count is what decides whether an absence of findings means anything. That enablement is a Defender plan the subscription buys rather than a setting it configures, so it qualifies the count below rather than deciding whether the expensive stage runs.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if the admin user is disabled on every registry, `anonymousPullEnabled` is off on every registry, and Defender for Containers vulnerability assessment reports no unresolved image assessment where it is enabled to look for one. Public network access without anonymous pull is reachability rather than access, so report the registry inventory with each registry's public network access and private endpoint connections, the assessment count with the enablement state that qualifies it, and the registration state of the resource providers named above, and which of the registry, assessment and provider reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the registries that are not clean:

Resolve which workloads pull from each by reading the container image references Resource Manager returns: Container Apps container images, App Service container settings, and the AKS cluster's attached registry list. Pod-level image references are not in Resource Manager, so where an AKS cluster attaches the registry say the cluster pulls from it without claiming which workloads do.

Report registries with the admin user enabled: the admin credential is a shared password with push permission that attributes to no principal in the registry logs. Report `anonymousPullEnabled` separately from public network access, since the first controls whether a caller needs credentials to read image contents and the second only controls reachability.

Resolve the role assignments granting `AcrPush` or a role containing `Microsoft.ContainerRegistry/registries/push/write` and report that principal set.

Where vulnerability assessment is enabled, filter the assessments to images a running workload references and report those with the workload's identity and network exposure. Where it is disabled, report the running image digests carrying no assessment.

Report a registry as intentional where the evidence supports it: a cache rule whose `sourceRepository` names a public upstream, which makes the registry a pull-through mirror of content that is already public, a scope map whose `actions` name only the repositories the subscription distributes, or a registry task that builds the images the registry serves. Name the evidence. An anonymously pullable registry with no such evidence is not intentional.


Order findings by risk, most consequential first.


Call shapes a run has proven:

Resource providers: `GET /subscriptions/{subscriptionId}/providers` on `management.azure.com`.

Defender for Cloud assessments: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments` on `management.azure.com`.
