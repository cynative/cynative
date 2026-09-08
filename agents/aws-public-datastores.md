---
description: Determine which AWS managed data services answer from public DNS and what authentication stands in front of each.
---

Research which RDS instances, Redshift clusters, OpenSearch domains, MSK clusters, DMS replication instances, Amazon MQ brokers and AppSync APIs in this account answer from public DNS, and what authentication stands in front of each. Whether the traffic to these endpoints is encrypted in transit is outside this agent's scope.

Read the service-level public flag on each: RDS `PubliclyAccessible` and instances outside a VPC, Redshift `PubliclyAccessible`, OpenSearch domains with no VPC options, MSK clusters with public access, DMS instances marked public, MQ brokers with public accessibility and AppSync APIs with visibility `GLOBAL`. All seven services named here are regional, so enumerate the enabled regions from the account and read once per region in that result rather than per region in a list of your own.

Read the authentication that stands in front of each in the same pass, because a network flag is only half the question this agent asks: whether each AppSync API's default authentication, or any of its additional authentication providers, is `API_KEY`, whether each OpenSearch domain has fine-grained access control enabled, and whether each MSK cluster permits unauthenticated client access. An OpenSearch domain inside a VPC with fine-grained access control off is a finding whatever the network flag says, because without it the domain's own access policy is what decides whether everything already in the VPC gets in, and that policy is resolved in the detailed stage below, not here.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no RDS instance or Redshift cluster has `PubliclyAccessible` set, no RDS instance sits outside a VPC, every OpenSearch domain has VPC options, every OpenSearch domain has fine-grained access control enabled, no MSK cluster has public access, no MSK cluster permits unauthenticated client access, no DMS instance is marked public, no MQ broker has public accessibility and no AppSync API has visibility `GLOBAL` with a default authentication or an additional authentication provider of `API_KEY`. Report the regions the sweep covered and the enabled-region listing it took them from, the counts by service, the OpenSearch domains with fine-grained access control disabled by name and whether each one's access policy restricts the principal, and the MSK clusters permitting unauthenticated client access by name, and which of the seven service enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the endpoints that are not clean:

Resolve the security groups and any service-level network policy in front of each, and report the admitted CIDRs with the finding. For an OpenSearch domain with fine-grained access control off, resolve its own access policy before calling it reachable by everything in the VPC: a policy naming IAM principals requires a signed request from one of them, and only a policy that does not restrict the principal admits every caller already inside.

Report the endpoints reachable without a credential first, which are the fine-grained-access-control cases whose access policy does not restrict the principal, and the unauthenticated-client cases, named in the counts, now with the security groups in front of them and what they hold. For public RDS, Redshift and MQ endpoints the finding is the exposure and the size of the admitted range. For AppSync, report the API key's expiry date and the API's resolvers.

Say what each exposed service holds by reading the resource's own metadata: engine, cluster identifier, database names where the API returns them, index or topic names. Do not infer contents from a resource name alone.

Report an endpoint as intentional where the evidence supports it: an OpenSearch access policy granting only `es:ESHttpGet` on a read-only index path, or an AppSync API whose only resolvers are queries against a dataset the account also publishes elsewhere. Name the evidence. An endpoint with no such evidence is not intentional.

Order findings by risk, most consequential first.

Call shapes a run has proven:

MSK: `GET /v1/clusters` on `kafka.<region>.amazonaws.com`.

OpenSearch: `GET /2021-01-01/domain` on `es.<region>.amazonaws.com`; a domain's own settings at `GET /2021-01-01/opensearch/domain/{name}`.

Redshift: `GET /?Action=DescribeClusters&Version=2012-12-01` on `redshift.<region>.amazonaws.com`.

Amazon MQ: `GET /v1/brokers` on `mq.<region>.amazonaws.com`.

AppSync: `GET /v1/apis` on `appsync.<region>.amazonaws.com`.

DMS: `X-Amz-Target: AmazonDMSv20160101.{Operation}` on `dms.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.
