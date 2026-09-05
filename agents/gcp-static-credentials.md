---
description: Find GCP service accounts holding broad roles with exportable keys, the impersonation chains between them and API keys with no restriction.
---

Research which service accounts in this organization hold a broad role together with an exportable key, and which API keys carry no restriction. Name the project of every account and key reported, and take the projects you enumerate from the organization's own project listing rather than from the project the credential defaults to, resolving which organization that is from the `parent` each project carries rather than from an organization listing, which the ceiling does not reach.

Read every service account's bindings at project, folder and organization level using Cloud Asset Inventory's organization-wide IAM policy search, together with its user-managed key count and, for each such key, whether it is disabled and whether it has passed its expiration, and read the API target and application restrictions on every API key. Read whether the default Compute Engine and App Engine service accounts still hold `roles/editor` at any of those levels.

A project that has not enabled the API Keys API holds no readable key rather than an unread one: take that service's enablement state from the project's own service listing, which returns each service with its state, and report a project where it is disabled as such rather than reporting the key enumeration as empty or as unresolved. That state answers the key enumeration and not the restrictions carried on a key: where the service is disabled the API target and application restrictions were not read, so name the API key read among the ones that did not answer for that project and do not report those restrictions as present, as clean or as absent. A key carrying no restriction is one of the objects this agent asks about, so where the service is disabled it was not read for that project rather than being absent from it, and the answer the report gives it is that it was not read. The report's first sentence gives the API keys their own answer on that basis rather than one shared with the objects that were read.

Read the organization policy `constraints/iam.disableServiceAccountKeyCreation` and the projects it applies at, from Cloud Asset's org-policy analysis for that named constraint, which returns the consolidated rules in force and the resource each result is attached to. It is the control for the exact condition this agent is about, so its state decides whether an existing key is a violation of enforcement or an exception granted before it.

`roles/iam.serviceAccountUser` is not a broad role for this purpose. Nearly every principal that deploys Cloud Run, Cloud Functions or Compute holds it, so counting it as broad would make the condition below fire almost nowhere; it is read and reported, and it earns a place in a finding only alongside a key on the same account.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no service account holding `roles/owner`, `roles/editor`, `roles/iam.serviceAccountTokenCreator` or a custom role containing `setIamPolicy` has a user-managed key that is neither disabled nor has passed its expiration, every API key is restricted to specific APIs and carries an application restriction other than an HTTP referrer, and the default Compute Engine and App Engine service accounts no longer hold `roles/editor`. Report the account and key inventory with each account's project, its service account bindings at project, folder and organization level and its user-managed key count, naming any disabled or past its expiration among them; the accounts holding `roles/iam.serviceAccountUser`; each API key's API target restrictions and application restrictions; and the `constraints/iam.disableServiceAccountKeyCreation` organization policy state with the projects the policy applies at; the API Keys API enablement state per project, and the count of projects the enumeration covered, and which of the service account, service account key, API key and organization policy reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the accounts and keys that are not clean:

Report the key count per account, each key's creation date and, where the API reports it, last authenticated time, and state whether `constraints/iam.disableServiceAccountKeyCreation` is enforced at that project: an unenforced constraint makes the key an ongoing capability, and an enforced one makes it a survivor that cannot be recreated.

Resolve which service accounts each holder of `roles/iam.serviceAccountTokenCreator` can impersonate and follow the chain until it terminates, then report the most privileged account reachable at the end.

For unrestricted API keys, resolve the project's enabled service list and report the subset of it that accepts API key authorization as the key's scope, since an unrestricted key reaches every one of those rather than the one it was cut for: a standard API key identifies its project rather than a principal, and carries no IAM binding to resolve. Name an enabled service that instead requires an IAM-authorized credential as enabled but not reached by the key, since a standard API key cannot stand in for one. A key restricted only by HTTP referrer carries no server-side restriction, so report the referrer restriction with the API target list rather than treating it as bounding, and report a key that names its APIs but carries no application restriction with the APIs it names, since the target list bounds what the key reaches and not who may present it.

Where the default service accounts still hold editor, report the count of instances and functions running as each.

Report a service account key as intentional where the evidence supports it: a workload outside GCP that the organization also names in a resource you can read, or an account whose only bindings are the single service the key's last authenticated call reached. Name the evidence. An exportable key on a broadly bound account with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Cloud Resource Manager: `GET /v3/projects:search`, and `GET /v3/projects?parent=organizations/{id}`, on `cloudresourcemanager.googleapis.com`.

Project IAM policy: `POST /v1/projects/{project}:getIamPolicy` on `cloudresourcemanager.googleapis.com`.

Service accounts and their keys: `GET /v1/projects/{project}/serviceAccounts` on `iam.googleapis.com`.

Cloud Asset: `GET /v1/organizations/{id}:analyzeOrgPolicies?constraint={constraint}` on `cloudasset.googleapis.com`; it carries an `x-goog-user-project` header naming the project the credential defaults to.

Service enablement: `GET /v1/projects/{project}/services/{service}` on `serviceusage.googleapis.com`; the enabled set at `GET /v1/projects/{project}/services?filter=state:ENABLED`.
