---
description: Find the Azure subscriptions, regions and alert paths where activity would produce no signal that reaches anyone.
---

Research which subscriptions in this tenant produce no signal from Defender for Cloud, no diagnostic setting and no working alert path. The subscription is the unit of comparison throughout, and every finding names the subscription it belongs to.

Enumerate the subscriptions, then per subscription read the Defender plan tier for each of these services: servers, App Service, Azure SQL, SQL servers on machines, open-source relational databases, storage, containers, Key Vault, Resource Manager, DNS and Cosmos DB. Read the enablement state of the `WDATP` security setting, which is where the Defender for Endpoint integration sits rather than in a plan tier, and each IoT security solution the subscription holds with whether it is enabled, which is a resource of its own and carries no plan tier either.

A subscription that has never bought a Defender plan has not registered `Microsoft.Security`, and a provider in that state holds none of its resource type rather than an unread one: take the registration state from the subscription's own provider listing, which returns every provider with its `registrationState`, rather than from a path naming one provider, and read the plan tiers, the `WDATP` setting and the IoT security solutions under an unregistered provider as absent rather than as unresolved. Absent is this agent's own finding and unresolved is a hole in it, so which of the two a subscription gets decides the answer rather than qualifying it.

Read the security contact address with its minimum alert severity and attack path risk level; whether a subscription-level diagnostic setting exists and which categories it captures; and whether activity log alerts exist for network security group create, update and delete and for policy assignment deletion, each with its action group.

Read Network Watcher enablement per region against the regions the subscription has resources in, and read NSG flow logs for enablement and destination.

Absence everywhere is not the same as absence in one place, but it is not an exemption either. A tenant with no plans, no diagnostic settings and no alerts anywhere is uniformly uncovered, which is the strongest form of the finding this agent looks for, so uniformity is a fact reported about a finding rather than a reason to stop. A subscription whose settings could not be read is unresolved rather than uncovered, and a tenant uniform in that is a bound on this report rather than the strongest form of anything.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every subscription has the `WDATP` setting enabled, has every IoT security solution it holds enabled, has a diagnostic setting capturing the Administrative, Security, Alert and Policy categories, has a security contact address with a minimum alert severity and an attack path risk level set, and has an activity log alert for network security group create, update and delete and for policy assignment deletion, each with an action group carrying at least one receiver. A Defender plan tier is a purchase the subscription makes rather than a setting it configures, so the tiers are reported below rather than tested here. Report the per-subscription plan tier table covering each of the services named above, the `WDATP` state and the status of each IoT security solution, the `registrationState` of `Microsoft.Security` per subscription, the Network Watcher enablement per region against the regions each subscription has resources in, and the NSG flow log enablement and destinations, and which of the per-subscription reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the subscriptions that are not clean:

Name what each uncovered subscription contains, name the services from the plan tier table above whose tier leaves it unwatched, and state whether it is uncovered alone or as part of a tenant-wide absence. A subscription that diverges from the rest of the tenant and a tenant that is uniformly uncovered are both findings; report the second once at the tenant level with the subscriptions it covers rather than repeating it per subscription.

Resolve each alert's action group and report alerts whose action group has no email, webhook or automation receiver. Do the same for the subscription's security contact: report an empty contact address with the configured minimum alert severity and attack path risk level.

Report flow logs written to storage with no Log Analytics workspace separately from flow logs being off: those are retained and unqueryable. Name the regions from the Network Watcher count above that hold resources and have no watcher.

Report an uncovered subscription as intentional where the evidence supports it: an empty subscription holding no resource of any type, or a subscription whose diagnostic settings are configured at a management group above it that the tenant also applies elsewhere. Name the evidence. A subscription holding resources with no such evidence is not intentional.


Order findings by risk, most consequential first.


Call shapes a run has proven:

Resource providers: `GET /subscriptions/{subscriptionId}/providers` on `management.azure.com`.
