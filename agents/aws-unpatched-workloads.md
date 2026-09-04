---
description: Rank AWS workloads on unsupported versions by network reachability and by what the Inspector findings against them report.
---

Research which RDS instances, EKS clusters, OpenSearch domains, ElastiCache clusters, Elastic Beanstalk environments and SSM-managed EC2 instances in this account run versions past support, and which of those are reachable.

Read the support status the provider API reports for each: RDS engine versions marked deprecated or past support, EKS clusters past their Kubernetes end-of-support date, Elastic Beanstalk environments without managed platform updates, and SSM patch compliance state with each instance's ping status and association state.

Read an OpenSearch domain's available service software update alongside its engine version rather than as that domain's support status: the update patches the managed service layer, and a domain on a fully supported engine version can still report one.

Read `AutoMinorVersionUpgrade` on ElastiCache Redis clusters together with the engine version. Below Redis 6 the flag is disabled and does not gate an upgrade path, so a disabled flag on an engine version older than 6 describes a setting rather than a stale workload and produces a finding nobody can act on. From Redis 6 it is the opt-in AWS uses for its minor-version upgrade campaigns.

Take the Inspector finding count per resource in the same pass, split by severity and by whether a fix is available. Inspector is enabled per region, so enumerate the enabled regions from the account and take the counts once per region in that result rather than per region in a list of your own. Its enablement comes from `inspector2:BatchGetAccountStatus`. Lower-severity findings and findings with no fix are inventory rather than a path.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if nothing is past support, every ElastiCache Redis cluster at engine version 6 or above has `AutoMinorVersionUpgrade` enabled, every Elastic Beanstalk environment has managed platform updates, no SSM-managed instance's patch compliance state is `NON_COMPLIANT` and Inspector reports no high or critical finding with a fix available. Report the version inventory by service with each RDS engine version and its support status, each EKS cluster's Kubernetes end-of-support date, each OpenSearch domain's engine version and the count of OpenSearch domains with an available service software update among the domains `es:ListDomainNames` returns, the `AutoMinorVersionUpgrade` state by engine version as a count, the Inspector finding counts by severity and fix availability, the SSM patch compliance state with the instance ping status and instance association state counts, and the regions the sweep covered and the enabled-region listing it took them from with the ones Inspector is not enabled in named among them as `inspector2:BatchGetAccountStatus` reports them, and which of the per-service enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the resources that are not clean:

Resolve whether each has a public endpoint or a security group admitting `0.0.0.0/0`, and report the reachable ones ahead of the rest.

Inspector findings carry a package, a severity, an exploit-availability field and a fix-availability field per resource. Rank on those fields rather than assessing vulnerabilities independently, filter to findings whose network reachability the finding itself reports, then resolve each affected instance's IAM role and include its permissions.

Separate unpatched instances from instances that are stopped, unregistered or have no baseline assigned, and name them within the compliance counts above.

Name the regions counted above where Inspector is not enabled and state that those regions are unassessed rather than reporting their instances as clean.

Report a workload past support as intentional where the evidence supports it: an extended-support subscription the API reports against the engine version, or an environment whose only network path is a security group admitting one application group and whose replacement is already running alongside it. Name the evidence. A stale workload with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

OpenSearch: `GET /2021-01-01/domain` on `es.<region>.amazonaws.com`; a domain's own settings at `GET /2021-01-01/opensearch/domain/{name}`.

Inspector: `POST /status/batch/get` on `inspector2.<region>.amazonaws.com`.

EKS: `GET /clusters` on `eks.<region>.amazonaws.com`.

RDS: `GET /?Action={Operation}&Version=2014-10-31` on `rds.<region>.amazonaws.com`.

ElastiCache: `GET /?Action={Operation}&Version=2015-02-02` on `elasticache.<region>.amazonaws.com`.

Elastic Beanstalk: `GET /?Action={Operation}&Version=2010-12-01` on `elasticbeanstalk.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.
