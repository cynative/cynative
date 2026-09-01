---
description: Determine which unencrypted AWS data can leave the service boundary, and where a KMS key policy is no narrower than the service permission behind it.
---

Research which EBS volumes and snapshots, RDS instances and clusters and snapshots, Redshift clusters, OpenSearch domains, Neptune clusters, Kinesis streams, SNS topics, SageMaker volumes and outputs, WorkSpaces volumes and Glue Data Catalog settings in this account store data unencrypted, and whether the keys behind the encrypted ones control anything.

Read the encryption state and the KMS key identifier on each, the EBS default encryption setting in each of the enabled regions the account's own region listing returns rather than in each region of a list of your own, `ReturnConnectionPasswordEncrypted` on the Data Catalog, the sharing attribute on every snapshot, and on every key in use - the keys the resources above record a KMS key identifier for, rather than every key the account holds - whose `KeyManager` is `CUSTOMER` its key policy and its automatic rotation state.

Neptune's clusters come back from the same `rds:DescribeDBClusters` enumeration as the RDS ones, told apart by `Engine`, rather than from an enumeration of its own. A SageMaker enumeration that did not reach the service leaves an unread scope rather than an account holding no SageMaker resource. WorkSpaces does not answer in every enabled region, so a region where it has no endpoint holds no volume rather than an unread one: name those regions among the ones the enumeration covered rather than reporting the fields as unresolved there. A Glue job's own security configuration is not in scope: the read that names one resolves to an action pair the ceiling does not grant in full, so the Data Catalog settings are the Glue encryption fact this agent carries.

A key policy granting the account root is the default and is not a narrowing: it delegates the decision to IAM, which is exactly the condition of a key set being no narrower than the service permission. Deciding whether a given key policy is narrower than the service permission means comparing two principal sets, so it is second-stage work and not a gate clause.

A condition narrows a `Principal: "*"` grant only where its operator belongs to the key's own type and its value is bounded. `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:SourceVpc` and `aws:SourceVpce` are string keys: they narrow under `StringEquals` with a literal value, and under `StringLike` only where the wildcard leaves the identifier itself fixed, so `o-*` under `StringLike` narrows nothing. `aws:SourceArn` and `aws:PrincipalArn` are ARN keys: they narrow under `ArnEquals`, and under `ArnLike` only where the account field of the pattern is literal. `aws:SourceIp` is an IP key: it narrows under `IpAddress` with a prefix other than `0.0.0.0/0` or `::/0`, and `NotIpAddress` on the same key does not narrow it. An IP key under a string operator, or an ARN key under `IpAddress`, is a type mismatch: do not credit it as a restriction, and report the statement as unresolved. The negated operators `StringNotEquals`, `StringNotLike`, `ArnNotEquals` and `ArnNotLike` exclude a set rather than bounding one, and neither they nor a condition value of `*` narrow the grant. A key that appears in the statement but does not apply to the grant, because it sits in a different statement or the action ignores it, does not narrow it either. Do not match on the presence of a key name anywhere in the serialized policy; evaluate the operator and the value against the statement that carries the grant.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every resource in scope is encrypted. The EBS default encryption setting and the Data Catalog's `CatalogEncryptionMode` are account-level settings rather than resources this account created, and both ship off in every region of every account, so a condition asserting them cannot be satisfied by an account holding nothing and they are counted below instead. Report the counts by resource type and region with `Engine` naming which cluster counts are Neptune and which RDS, the KMS key identifier recorded against each encrypted resource, the sharing attribute on each snapshot, the EBS default encryption setting in each enabled region, `CatalogEncryptionMode` and `ReturnConnectionPasswordEncrypted` on the Data Catalog in each enabled region, the keys whose `KeyManager` is `CUSTOMER` with automatic rotation disabled as a count, and the customer managed keys whose key policy grants `kms:Decrypt` to a principal beyond the service principal that uses the key as a count, and which of the per-service enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the resources and keys that are not clean:

Report unencrypted resources by whether the data can leave the service boundary. Where `ReturnConnectionPasswordEncrypted` is false, the Data Catalog returns connection passwords in the clear to every principal that can read a connection. Use a snapshot's sharing attribute to rank its encryption finding. Everything else belongs in a grouped count.

For the keys whose policy names a broader principal, compare the principals granted `kms:Decrypt` in the policy and the key's grants against the principals holding the service-level read permission on the resource, and report the resources where the key set is no narrower, since there the key adds no control.

Where EBS default encryption is off, report the creation time of the most recent unencrypted volume, since every volume created while the setting stays off defaults to unencrypted.

Report the keys with automatic rotation disabled in full where the key also protects a resource shared outside the account or named in a finding above, and leave the rest in the count.

Report an unencrypted resource as intentional where the evidence supports it: a service that does not support encryption at rest for that resource type at all, or a resource whose only content the account also publishes without restriction elsewhere. Name the evidence. An unencrypted resource with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

KMS: `X-Amz-Target: TrentService.{Operation}` on `kms.<region>.amazonaws.com`.

OpenSearch: `GET /2021-01-01/domain` on `es.<region>.amazonaws.com`; a domain's own settings at `GET /2021-01-01/opensearch/domain/{name}`.

Neptune and DocumentDB: the RDS API on `rds.<region>.amazonaws.com`.

SageMaker: `X-Amz-Target: SageMaker.ListNotebookInstances` and `X-Amz-Target: SageMaker.ListTrainingJobs`, with a `Content-Type` of `application/x-amz-json-1.1`, on `api.sagemaker.<region>.amazonaws.com`.

Redshift: `GET /?Action=DescribeClusters&Version=2012-12-01` on `redshift.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`; the account default at `GET /?Action=GetEbsEncryptionByDefault&Version=2016-11-15`, and the account's own snapshots at `GET /?Action=DescribeSnapshots&Owner.1=self&Version=2016-11-15`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.
