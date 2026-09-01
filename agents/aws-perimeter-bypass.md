---
description: Find AWS Network Firewall and WAF deployments that pass traffic without inspecting it, and the subnets whose routes bypass them.
---

Research which Network Firewall policies and WAF Web ACLs in this account are deployed but pass traffic without inspecting it, and which subnets route around them.

Read each firewall policy's rule group references, its stateless default actions for both full and fragmented packets and its logging configuration; each WAFv2 and WAF Classic Web ACL's rules with the rule group references those rules carry, which the Web ACL itself returns rather than the rule group; and each Web ACL's resource associations. Network Firewall and the regional WAFv2 scope are regional, so enumerate the enabled regions from the account and list firewalls, policies and Web ACLs once per region in that result rather than per region in a list of your own. The CloudFront WAFv2 scope and WAF Classic global are not regional, so read each once rather than once per region: a per-region sweep of a global scope returns sixteen empty answers and reports them as sixteen regions holding no Web ACL.

Read the firewall's subnet mappings alongside the route tables of every subnet in the VPC those mappings name, taking that subnet set from the VPC itself rather than from the account's whole subnet listing. Firewall endpoints exist per Availability Zone, so a policy that is correct in every field it carries still inspects nothing in a zone whose subnets route to the internet gateway without traversing an endpoint. That comparison is two describes rather than a per-resource resolution, which is why it belongs before the gate rather than after it.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every policy has a rule group associated, drops by default or forwards by default to a stateful rule group for both full and fragmented packets and has logging enabled, every Web ACL carries at least one rule, and every subnet with a route to an internet gateway traverses a firewall endpoint. Report the regions the sweep covered and the enabled-region listing it took them from, the firewall and Web ACL inventory with each policy's rule group references and its stateless default actions for full and fragmented packets, each Web ACL's rules with their rule group references and its resource associations, each firewall's logging configuration, and each firewall's subnet mappings set against the route tables of the subnets in its VPC by Availability Zone, and which of the firewall, Web ACL, subnet and route table enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the policies, ACLs and subnets that are not clean:

Report which of three states each firewall is in: no rule group associated, a full-packet default of `aws:pass`, or a default of `aws:forward_to_sfe` with no stateful rule groups behind it. Report the fragmented-packet default separately, since a policy dropping full packets and passing fragments passes fragmented traffic.

For each bypassing subnet, report the route table entry that reaches the internet gateway, the Availability Zone it sits in and the instances and load balancer interfaces in it, since those are what the firewall never sees. A subnet holding neither belongs in a count: the route goes around the firewall, but there is nothing in it whose traffic the firewall is missing.

Report each firewall whose logging is disabled with the rule groups it does evaluate, since those decisions leave no record.

Report each empty Web ACL with the CloudFront distributions, load balancers and API Gateway stages its resource associations name, which the association listing returns as ARNs without a call to the fronted service. An ACL with no associations is dead configuration and belongs in a count.

Report an empty Web ACL or an unfiltered subnet as intentional where the evidence supports it: a Web ACL whose only associations are already fronted by another ACL carrying rules, or a subnet whose route to the internet gateway serves an interface the firewall's own management path requires. Name the evidence. An ACL or subnet with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

WAFv2: `X-Amz-Target: AWSWAF_20190729.{Operation}` on `wafv2.<region>.amazonaws.com`, with the `CLOUDFRONT` scope on `us-east-1`.

WAF Classic: `X-Amz-Target: AWSWAF_Regional_20161128.ListWebACLs` on `waf-regional.<region>.amazonaws.com`; the global scope at `X-Amz-Target: AWSWAF_20150824.ListWebACLs` on `waf.amazonaws.com`.

Network Firewall: `X-Amz-Target: NetworkFirewall_20201112.{Operation}` on `network-firewall.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.
