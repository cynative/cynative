---
description: Expand GCP firewall rules to the instances they actually select, and report what each reachable instance's service account holds.
---

Research which Compute Engine instances in this organization a firewall rule actually exposes to the internet on SSH or RDP, and what each reachable instance's service account holds. Name the project of every instance reported, and take the projects you enumerate from the organization's own project listing rather than from the project the credential defaults to, resolving which organization that is from the `parent` each project carries rather than from an organization listing, which the ceiling does not reach.

List ingress rules with a source range of `0.0.0.0/0` on TCP 22 or TCP 3389, and list the running instances with an external IP on a network interface. A rule admits that traffic only where it allows and is not disabled: one that denies the same source blocks the traffic rather than admitting it, and a disabled rule admits nothing at all. Rules select instances by target tag, by target service account, or, where neither is set, every instance in the network; on the source side a rule may also be narrowed by `sourceTags` or `sourceServiceAccounts`, which admit only traffic from instances carrying them rather than from the internet, so read both before calling a rule open.

Firewall rules attach to a VPC network rather than to an instance, so an instance with interfaces on two networks is governed by two different rule sets. Resolve rules per interface and report the network each conclusion belongs to.

A source range of `35.235.240.0/20` on 22 or 3389 is Identity-Aware Proxy TCP forwarding rather than the internet: that block is the forwarder's own range, so reaching the port through it requires an IAM permission first. Read it as a bounded source and not as an open one.

Read OS Login and its two-factor setting at project and instance level, since instance metadata overrides the project value.

A project that has not enabled the Compute Engine API holds no instance, firewall rule or address rather than unread ones: take that service's enablement state from the project's own service listing, which returns each service with its state, and report a project where it is disabled as such rather than reporting its enumerations as empty or as unresolved.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no ingress rule with a source of `0.0.0.0/0` reaches TCP 22 or TCP 3389 on a network whose instances carry an external IP, or if no running instance has an external IP. Report the rule count by source range and destination port with the rules that deny or are disabled and the `35.235.240.0/20` and `sourceTags` or `sourceServiceAccounts` rules counted apart from the rules that allow and each rule split by whether it selects by target tag, by target service account or by neither, the instance count with external IPs by project and VPC network, one line per network interface, the OS Login and two-factor state both at project level and in instance metadata, and the count of projects the enumeration covered, the service enablement state for the Compute Engine API per project, and which of the rule, instance and metadata reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the rules and instances that are not clean:

Expand each rule's target set - instances carrying the tag, instances running as the named service account, or all instances in the network where the rule has no target - and report the rule with the running externally-addressed instances it selects, one line per interface rather than per instance. A rule that selects none of them belongs in a count: the port is open to the internet and nothing answers on it.

For each reachable instance, report its service account and access scopes. Where an instance runs as the default Compute Engine service account with the `cloud-platform` scope, resolve that account's project bindings and report them with the instance.

With OS Login enforced, report the principals holding `compute.instances.osLogin` or `compute.instances.osAdminLogin`. With it disabled, access is by SSH keys in instance or project metadata, so report the principals holding `compute.instances.setMetadata` or `compute.projects.setCommonInstanceMetadata` instead.

Report an open rule as intentional where the evidence supports it: a source range of `35.235.240.0/20` with the principals holding `iap.tunnelInstances.accessViaIAP` named, instances that enforce OS Login with two-factor authentication and a named group holding the login permissions, or a service account holding nothing beyond its own workload. Name the evidence. A rule reaching 22 or 3389 from the internet with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Service enablement: `GET /v1/projects/{project}/services/{service}` on `serviceusage.googleapis.com`.

Cloud Resource Manager: `GET /v3/projects:search`, and `GET /v3/projects?parent=organizations/{id}`, on `cloudresourcemanager.googleapis.com`.

Project IAM policy: `POST /v1/projects/{project}:getIamPolicy` on `cloudresourcemanager.googleapis.com`.

Compute Engine: `GET /compute/v1/projects/{project}/aggregated/instances` and `GET /compute/v1/projects/{project}/global/firewalls` on `compute.googleapis.com`.
