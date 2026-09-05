---
description: Report AWS services carrying traffic without TLS against the CIDRs admitted to their ports, together with the certificates behind them.
---

Research which RDS instances and clusters, DMS endpoints, MSK clusters and connectors, Redshift clusters, OpenSearch domains, Transfer Family servers and SNS subscriptions in this account carry traffic without TLS, and what shares the network path to each. Whether these endpoints answer from public DNS at all is outside this agent's scope.

Read the in-transit setting on each, the `ClientAuthentication` configuration on any MSK cluster with a plaintext listener, and the endpoint protocol on every SNS subscription. Every service named here is regional, so enumerate the enabled regions from the account and read once per region in that result rather than per region in a list of your own.

Read the expiry dates and key algorithms on ACM certificates, RDS certificate authorities and IAM server certificates, and the resource each certificate is attached to. Certificate expiry is an availability property rather than a transport-encryption failure, so it is reported alongside rather than deciding whether the expensive stage runs. ACM does not issue certificates below RSA-2048 or the equivalent curve strength, so a weak key algorithm only ever describes an imported certificate. An RDS certificate authority is published by AWS into every account rather than issued to this one, and every account holds the same set of them, so what to read is which authority each DB instance references; the rest are not certificates this account holds and are not certificates attached to nothing.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every resource enforces TLS in transit and no SNS subscription uses an `http` endpoint. Report the regions the sweep covered and the enabled-region listing it took them from, the in-transit setting counts by service, the SNS subscription endpoint protocols as a count, the `ClientAuthentication` configuration on every MSK cluster with the count of those carrying a plaintext listener, the ACM, RDS and IAM server certificate inventory with the certificate authority reference each RDS instance names and with each certificate's expiry date, key algorithm and attached resource, and the ACM and IAM server certificates attached to nothing as a count, and which of the per-service enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the resources that are not clean:

Resolve the security groups permitting the resource's port, the CIDRs those groups admit, and any VPC peering connection or Transit Gateway attachment on its subnet's route table. Report the admitted CIDRs with each finding: a resource not enforcing TLS whose port is admitted from one application security group is bounded, and the same setting on one admitting a peered VPC, a VPN range or `0.0.0.0/0` is not.

Report MSK clusters whose plaintext listener also permits unauthenticated access, and MSK connectors without in-transit encryption, ahead of the rest. For SNS subscriptions with an `http` endpoint, read what publishes to the topic and report the message source.

Name the certificates from the inventory above that are expired or expire within 30 days against the resources they are attached to, and report an imported certificate below RSA-2048 or the equivalent curve strength as a finding where it is attached to an internet-facing distribution or load balancer.

Report a resource not enforcing TLS as intentional where the evidence supports it: a port admitted only from a security group whose members are all in the same application, or a replication endpoint whose peer is another resource in this account on a subnet with no route beyond the VPC. Name the evidence. A plaintext path with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

OpenSearch: `GET /2021-01-01/domain` on `es.<region>.amazonaws.com`; a domain's own settings at `GET /2021-01-01/opensearch/domain/{name}`.

MSK: `GET /v1/clusters` on `kafka.<region>.amazonaws.com`.

MSK Connect: `GET /v1/connectors` on `kafkaconnect.<region>.amazonaws.com`.

Transfer Family: `X-Amz-Target: TransferService.{Operation}` on `transfer.<region>.amazonaws.com`.

ACM: `X-Amz-Target: CertificateManager.{Operation}` on `acm.<region>.amazonaws.com`.

Redshift: `GET /?Action=DescribeClusters&Version=2012-12-01` on `redshift.<region>.amazonaws.com`.

DMS: `X-Amz-Target: AmazonDMSv20160101.{Operation}` on `dms.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.
