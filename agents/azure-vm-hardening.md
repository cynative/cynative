---
description: Determine the paths to a session on each Azure virtual machine or to the contents of its disks, and what each path requires.
---

Research how someone gets a session on the virtual machines in this subscription or reads their disks, and what each path requires.

Read `disablePasswordAuthentication` on every Linux machine, whether each machine uses managed or unmanaged disks, each machine's image reference and publisher, and the Azure Backup, endpoint protection and system update assessment states, taking all three from Defender for Cloud's assessment results, which carry one per machine and cost one call for the three. A Windows machine carries no such field: count the Windows machines, and report their authentication path as not read rather than folding them into a clean result. The per-machine patch route is an assessment this agent must not take: the operation that produces a fresh one runs on the machine. Read which role definitions include `Microsoft.Compute/virtualMachines/runCommand/action` together with their assignments.

A machine enumeration returns standalone machines and not the instances inside a virtual machine scale set, so a subscription whose compute is a scale set returns none of them: count the scale sets and the instances in each, so that the report names the machines this agent did not assess rather than reporting that the subscription holds no machines. What runs inside a scale set instance - its own authentication, its own disks, its own image - is outside this agent's scope, and the count is what tells a reader that.

The run-command action executes arbitrary commands as root or SYSTEM through the Azure control plane with no network path and no key. It is included in Virtual Machine Contributor and in Contributor, both of which are ubiquitous, so its holder set is an inventory to report rather than a condition that decides anything: an account where only Owner holds it does not exist in practice.

The assessment collection those three states come from is empty both where Defender is watching and has nothing to report and where no Defender plan was ever bought, and nothing in the collection tells the two apart. A subscription that has never bought one has not registered `Microsoft.Security`, and a provider in that state holds none of its resource type rather than an unread one: take the registration state from the path naming `Microsoft.Security` alone, which returns its `registrationState` in a body that fits, rather than from the subscription's own whole-provider listing, and let it qualify the three counts rather than deciding whether the expensive stage runs - the plan is a purchase the subscription makes rather than a setting it configures.

Unmanaged disks are close to end of life on Azure and most subscriptions have none. Read the field, but expect the branch to be empty and report it as a count when it is, rather than treating its absence as a result.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if `disablePasswordAuthentication` is true on every Linux machine and every machine uses managed disks. A custom image is a build decision rather than a path, so report the image reference and publisher inventory alongside the machine inventory, the Windows machine count, the set of principals holding `Microsoft.Compute/virtualMachines/runCommand/action` with the role definition and role assignments each holds it through, the disk type of each machine as managed and unmanaged counts, the scale set count with the instances in each, and the Azure Backup, endpoint protection and system update assessment states as counts with the `registrationState` of `Microsoft.Security` that qualifies them, and which of the machine, disk, image and assessment reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the machines and principals that are not clean:

Report password-authentication machines with the inbound rules on their network interface and subnet, both of which apply in priority order, since the password is only reachable where a rule admits the port.

Report each run-command holder from the inventory above with the machines its assignment scope reaches. The action executes on every machine under the scope of the assignment rather than on a machine the assignment names, so a holder at subscription scope reaches every machine in it.

For unmanaged disks, resolve the storage account holding each VHD and report its `publicNetworkAccess`, network default action and `allowSharedKeyAccess`, since those govern the disk rather than any setting on the machine.

Report machines running a custom or gallery image rather than a platform publisher image, with the image resource, its `publishedDate` where it is a gallery image version, and how many machines reference it, and name the affected machines within the backup, endpoint protection and system update counts. A managed image carries no date of its own, so report it by its source virtual machine instead.

Report a custom image as intentional where the evidence supports it: many machines referencing one image, or a build pipeline resource in the subscription that produces it. Name the evidence. A custom image with a single consumer and with no such evidence is not intentional.


Order findings by risk, most consequential first.


Call shapes a run has proven:

Resource providers: `GET /subscriptions/{subscriptionId}/providers/{resourceProviderNamespace}` on `management.azure.com`.

Defender for Cloud assessments: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments` on `management.azure.com`.
