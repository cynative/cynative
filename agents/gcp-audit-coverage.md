---
description: Determine which activity in a GCP organization would go unrecorded, from the audit configuration each project carries, its load balancer logging and its asset inventory.
---

Research which activity in this organization would go unrecorded, and in which projects. Name the project of every resource reported, and take the projects you enumerate from the organization's own project listing rather than from the project the credential defaults to, resolving which organization that is from the `parent` each project carries rather than from an organization listing, which the ceiling does not reach.

Read the IAM audit configuration on each project, whether each HTTP(S) load balancer has logging enabled, and whether the Cloud Asset Inventory API is enabled. The logging state sits on the load balancer's backend services.

`DATA_READ` is off by default for most services, so its absence is the normal state and requiring it everywhere would describe an ideal rather than a baseline. What distinguishes a finding is divergence: a project whose audit configuration differs from the pattern the organization's other projects share. Comparing the configurations already read is not a further call, which is why that comparison sits in the condition below rather than after it.

A project that has not enabled the Compute Engine API holds no load balancer rather than an unread one: take that service's enablement state from the project's own service listing, which returns each service with its state, and report a project where it is disabled as such rather than reporting the logging state as unresolved.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every HTTP(S) load balancer has logging enabled, Cloud Asset Inventory is enabled and no project's IAM audit configuration diverges from the pattern the organization's other projects share. Report the IAM audit configuration per service showing which services have `DATA_READ` enabled and which do not, the HTTP(S) load balancer logging state as a count, the Cloud Asset Inventory enablement state, and the count of projects the enumeration covered, the service enablement state for the Compute Engine API per project, and which of the audit configuration, load balancer and asset inventory reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the projects that are not clean:

Report each divergent project with the services whose `DATA_READ` state differs from the organization's pattern. Uniform absence across the whole organization is a volume decision rather than drift, so report it once naming the projects it covers rather than once per project.

Report load balancers with logging disabled together with their backend services.

Report an absent `DATA_READ` configuration as intentional where the evidence supports it: a project matching the organization's pattern where at least one other project does enable `DATA_READ`, since an organization that enables it nowhere is an unaudited organization rather than a pattern, or an audit configuration that enables `DATA_READ` for other services in the same project, which makes this service a selection rather than an omission. Name the evidence. A project diverging from the organization's pattern with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Service enablement: `GET /v1/projects/{project}/services/{service}` on `serviceusage.googleapis.com`.

Cloud Resource Manager: `GET /v3/projects:search`, and `GET /v3/projects?parent=organizations/{id}`, on `cloudresourcemanager.googleapis.com`.

Project IAM policy: `POST /v1/projects/{project}:getIamPolicy` on `cloudresourcemanager.googleapis.com`.

Compute Engine: `GET /compute/v1/projects/{project}/global/backendServices` on `compute.googleapis.com`.
