---
description: Resolve the effective inbound NSG rules per interface and report the ones reaching a running machine, with that machine's managed identity.
---

Research which network security group rules in this subscription admit inbound traffic from the internet to a running virtual machine, and what that machine's managed identity holds.

List inbound allow rules whose source is `Internet`, `*`, `0.0.0.0/0` or `::/0`, taking the destination port range with each, list the public IP addresses in the subscription with the resource each is attached to, list the load balancers with their frontend IP configurations, their inbound NAT rules and the interface each reaches, and their load-balancing rules with the backend pool membership behind each, and list the subnets with no network security group associated.

The ports that rank are the management and data-store ports, where the service either authenticates weakly or answers before it authenticates: TCP 22 and 3389 for interactive sessions, and TCP 445, 1433, 3306, 5432 and 27017 for file shares and databases. TCP 80 is the port a web tier exists to serve, so a rule admitting it is counted rather than ranked, and becomes a finding only where the machine behind it serves no web application. A UDP rule is a finding where its destination range covers a port other than 443, 500 and 4500 - QUIC and IPsec - or spans the whole range, since a UDP service answering an unsolicited datagram needs no handshake first.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no inbound allow rule from `Internet`, `*`, `0.0.0.0/0` or `::/0` reaches TCP 22, 3389, 445, 1433, 3306, 5432 or 27017 or a UDP range outside 443, 500 and 4500, or if no interface in any subnet those rules govern has a public IP address, a load balancer inbound NAT rule, or backend pool membership behind a load-balancing rule with a public frontend. Report the rule count by destination port range, the TCP 80 rules as a count, the UDP rules with their destination port ranges, the public IP addresses with the resource each is attached to, and the subnets with no network security group associated, and which of the rule, interface, address and subnet enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the rules that are not clean:

Resolve the effective inbound rule set per interface from the group associated with the interface and the group associated with its subnet, both of which the rule listing above already returned, rather than asking the platform for the effective set: that operation is `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action`, an action rather than a read. The two groups are evaluated independently, each over its allow and deny rules together, including its default deny rule, in its own priority order with the first match winning, and traffic reaches the interface only where both admit it, so report the effective outcome, naming the deny rule or default deny that blocks it where one does, rather than a single allow rule. Report whether the attached virtual machine is running.

For each reachable machine, read its system-assigned and user-assigned managed identities and their role assignments, and report those with the rule.

Name the machines behind the TCP 80 count above and report the rule as a finding where the machine has no web workload - no application gateway or load balancer backend membership and no web listener among its other admitted ports.

Report each UDP rule individually with its destination port range and the service that answers on it where the machine's other configuration names one.

Report a subnet with no network security group as a finding only where an interface in it also has no group and carries a public IP; otherwise leave the association gap in the count above.

Report a rule as intentional where the evidence supports it: an interface in a load balancer backend pool whose health probe passes on the same port, or an application gateway subnet whose required inbound ranges the platform mandates. Name the evidence. A management or data-store port open to the internet with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Network resources: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups` on `management.azure.com`, and the same subscription-wide form for `networkInterfaces`, `virtualNetworks`, `publicIPAddresses`, `loadBalancers` and `applicationGateways`.

Virtual machines: `GET /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines` on `management.azure.com`; scale sets at `GET /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets`, and one set's members at `GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{scaleSetName}/virtualMachines`.

Managed identities: `GET /subscriptions/{subscriptionId}/providers/Microsoft.ManagedIdentity/userAssignedIdentities` on `management.azure.com`; role assignments at `GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments`.

Subscriptions and their contents: `GET /subscriptions` on `management.azure.com`; the resource inventory at `GET /subscriptions/{subscriptionId}/resources` and the group listing at `GET /subscriptions/{subscriptionId}/resourcegroups`.
