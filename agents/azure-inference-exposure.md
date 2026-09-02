---
description: Determine which Azure OpenAI accounts and AI Search services are reachable from outside the subscription and what a caller reaching one obtains.
---

Research which Azure OpenAI accounts and AI Search services in this subscription answer a caller from outside, and what reaching one obtains.

Read the Cognitive Services accounts that host OpenAI model deployments for public network access, their network ACL default action and rules and whether local key authentication is disabled, the API Management endpoints that front them for a subscription or product requirement, and the AI Search services for public network access, their network ACL default action and rules, and whether local key authentication is disabled via `disableLocalAuth` or `authOptions`. Such an account carries a kind of `OpenAI` where it was created for that service alone and a kind of `AIServices` where it was created as the multi-service resource, and both serve deployments of OpenAI-format models on the account's own hostname, so an enumeration filtered to the first kind alone reports an account of the second as absent rather than reading it. Azure OpenAI is where an Azure tenant runs inference, so an agent that reads only the gateway in front of it reports on the door and not the room.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no Azure OpenAI account or AI Search service is publicly reachable with local key authentication enabled. Report the public network access and network ACL default action and rules on each Cognitive Services account of kind `OpenAI` or `AIServices` and each AI Search service, whether local key authentication is disabled on each account and service via `disableLocalAuth` or `authOptions`, the API Management endpoints in front of them with the subscription and product requirements each carries, and the count of accounts and services the enumeration covered, and which of the account, gateway and search enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the accounts and services that are not clean:

Report each reachable account or service with whether local key authentication is disabled, since an endpoint that accepts only a tenant identity and one that accepts a key are different exposures: the first needs a principal the tenant governs and the second needs a string that can be copied.

Report the model deployments on each reachable account, since a deployment is what a caller spends against and an account carrying none exposes a control plane rather than inference.

Report the API Management endpoint in front of each reachable account with its subscription and product requirement, and where the account answers on its own hostname as well, report that the gateway is beside the account rather than in front of it.

Report a reachable account or service as intentional where the evidence supports it: an API Management product with a subscription requirement in front of it and no direct path to the account's own hostname, or a network ACL default action of `Deny` with the caller's range named in the rules. Name the evidence. An account or service answering without a credential and with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Cognitive Services: `GET /subscriptions/{subscriptionId}/providers/Microsoft.CognitiveServices/accounts` on `management.azure.com`; one account's own settings at `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.CognitiveServices/accounts/{accountName}`, and its deployments at that path followed by `/deployments`.

AI Search: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Search/searchServices` on `management.azure.com`.

API Management: `GET /subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/service` on `management.azure.com`.

Subscriptions and their contents: `GET /subscriptions` on `management.azure.com`; the resource inventory at `GET /subscriptions/{subscriptionId}/resources`.
