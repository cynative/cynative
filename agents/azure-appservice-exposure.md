---
description: Determine how code and requests reach Azure App Service and Function apps, and what each app's managed identity holds.
---

Research which App Service web apps and Function apps in this subscription accept code or requests from outside, and what each app's managed identity can do with them.

Read the `ftp` and `scm` basic publishing credentials policies, `ftpsState`, `httpsOnly`, the public network access and access restriction configuration, and the `authLevel` on every HTTP-triggered function.

The two publishing endpoints differ. Basic credentials over FTP with `ftpsState` at `AllAllowed` put the publishing password on the wire in cleartext; the same credentials over SCM travel inside HTTPS, so there the finding is that a password authenticates a code push at all rather than that it is exposed in transit.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if basic publishing credentials are disabled for both `ftp` and `scm` on every app and no HTTP-triggered function is at `authLevel: anonymous`. A web app reachable from the internet is what App Service is for, so treat public network access and the access restriction configuration as attributes of the findings below rather than conditions of their own. Report the app inventory with the public network access and access restriction configuration, the `httpsOnly` state as a count, the `ftpsState` values as a count, and the `authLevel` distribution across HTTP-triggered functions, and which of the app and function enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the apps that are not clean:

Where basic credentials are enabled and `ftpsState` is `AllAllowed`, report the app with its managed identity role assignments, since the publishing password crosses the network in cleartext and permits replacing the code that runs as that identity. Report SCM basic credentials separately with the same role resolution.

Report Function apps with anonymous HTTP triggers, naming the functions, the app's public network access setting and the identity's role assignments. Report `authLevel: admin` triggers alongside them: the key that satisfies an admin trigger is the host master key, which is one credential for every function in the app, so treat holding it as reaching the whole app rather than one route.

Name the apps behind the `httpsOnly` count above together with whether each has an authentication provider configured.

Report an anonymous function as intentional where the evidence supports it: a function named or routed as a health probe that an application gateway or load balancer in the subscription references, or an Event Grid or Logic App subscription in the subscription that targets it. Name the evidence. An anonymous trigger with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Web and Function apps: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Web/sites` on `management.azure.com`; the same listing scoped to one group at `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites`.

Role assignments and definitions: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments` and `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions`, on `management.azure.com`.

Subscriptions and their contents: `GET /subscriptions` on `management.azure.com`; the resource inventory at `GET /subscriptions/{subscriptionId}/resources` and the group listing at `GET /subscriptions/{subscriptionId}/resourcegroups`.
