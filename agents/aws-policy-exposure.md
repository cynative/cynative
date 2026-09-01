---
description: Classify every non-storage AWS resource policy as anonymous, external-account or internal, and resolve the outside accounts each one names.
---

Research which Lambda functions, SNS topics, SQS queues, SES identities, Secrets Manager secrets, KMS keys, EventBridge buses and schema registries, CloudWatch log groups, Glue Data Catalogs, VPC endpoints and endpoint services and Transit Gateways in this account grant access to a principal outside the account, and what that principal can do.

Fetch each resource policy plus Lambda function URLs with an `AuthType` of `NONE`, taking a schema registry's policy from `schemas:GetResourcePolicy` for the registries the registry listing returns outside the `aws.` namespace, since a registry inside it is AWS-managed and carries no policy this account sets, VPC endpoint service allowed principals, Transit Gateway auto-accept settings, the Organizations delegated administrator list and every IAM role trust policy, which the role listing returns with each role rather than needing a read of its own or the account's whole authorization detail, and classify every statement as anonymous, external-account or internal. Take the SES identities and their policies from the SES identity and identity-policy listings. Take the Glue Data Catalog's policy from `glue:GetResourcePolicy`, which returns the catalog's own policy, rather than from the catalog-wide policy listing. A KMS key policy granting the account root is the default rather than an exposure. On every key whose `KeyManager` is `CUSTOMER` and whose `KeyState` is `Enabled`, read its aliases, description and tags, and treat it as an enclave key where any of them carries `enclave` or where its policy already names a `kms:RecipientAttestation` condition key. On those keys take each `Allow` granting `kms:Decrypt`, `kms:DeriveSharedSecret`, `kms:GenerateDataKey`, `kms:GenerateDataKeyPair` or `kms:GenerateRandom`, which are the operations that hand back plaintext or key material, and record whether it carries a `kms:RecipientAttestation` condition and whether a `Deny` elsewhere in the same policy withholds the action from a caller that presents none. That condition is what ties such a grant to a measured enclave, so an `Allow` without one and with no `Deny` behind it opens the key to every principal IAM already admits. Read which accounts this organization holds, because that is what places an account inside it or outside. Every resource named here except the IAM roles is regional, so enumerate the enabled regions from the account and read once per region in that result rather than per region in a list of your own.

A service-linked role, whose ARN sits under `aws-service-role`, is outside the trust-condition count below: AWS writes that trust and the account cannot change it, so a missing `aws:SourceAccount` or `aws:SourceArn` on one is not a gap anyone here can close.

A condition narrows a `Principal: "*"` grant only where its operator belongs to the key's own type and its value is bounded. `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:SourceVpc` and `aws:SourceVpce` are string keys: they narrow under `StringEquals` with a literal value, and under `StringLike` only where the wildcard leaves the identifier itself fixed, so `o-*` under `StringLike` narrows nothing. `aws:SourceArn` and `aws:PrincipalArn` are ARN keys: they narrow under `ArnEquals`, and under `ArnLike` only where the account field of the pattern is literal. `aws:SourceIp` is an IP key: it narrows under `IpAddress` with a prefix other than `0.0.0.0/0` or `::/0`, and `NotIpAddress` on the same key does not narrow it. An IP key under a string operator, or an ARN key under `IpAddress`, is a type mismatch: do not credit it as a restriction, and report the statement as unresolved. The negated operators `StringNotEquals`, `StringNotLike`, `ArnNotEquals` and `ArnNotLike` exclude a set rather than bounding one, and neither they nor a condition value of `*` narrow the grant. A key that appears in the statement but does not apply to the grant, because it sits in a different statement or the action ignores it, does not narrow it either. Do not match on the presence of a key name anywhere in the serialized policy; evaluate the operator and the value against the statement that carries the grant.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no statement is anonymous and none names an account outside the organization. Report the regions the sweep covered and the enabled-region listing it took them from, the resource policy count by service with each statement classified as anonymous, external-account or internal, including the Glue Data Catalog policy `glue:GetResourcePolicy` returns, the schema registry policy `schemas:GetResourcePolicy` returns and the SES identity policies `ses:GetIdentityPolicies` returns for the identities `ses:ListIdentities` and `ses:ListIdentityPolicies` name, and the catalog, registry and identity policy statements inside that count, the KMS key policies granting nothing beyond the account root as a count, the keys whose `KeyManager` is `CUSTOMER` and whose `KeyState` is `Enabled` that their aliases, description or tags mark as enclave keys, each with the sensitive `Allow` statements carrying no `kms:RecipientAttestation` condition and whether a `Deny` covers them, the Lambda function URLs with an `AuthType` of `NONE`, the VPC endpoint services with their allowed principals, the Transit Gateways with auto-accept enabled, the Organizations delegated administrator list, and the count of service role trust policies carrying neither an `aws:SourceAccount` nor an `aws:SourceArn` condition, with the service-linked roles that count excludes counted apart from it, the count of accounts the organization holds, stated as this account being in no organization where that is the answer, and which of the per-service policy enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the statements that are not clean:

Resolve each external account ID against the organization's account list and against the other trust policies in the account. Report in full any ID appearing in exactly one policy with no other occurrence; IDs appearing consistently across many policies belong in a summary line.

For anonymous statements permitting `lambda:InvokeFunction`, `sqs:SendMessage`, `sns:Publish` or `events:PutEvents`, identify what consumes the input and report that with the statement. Rank those and anonymous read on secrets and keys above the rest.

Name the service roles counted above whose trust policy carries neither condition, in full where the trusted service is one that assumes across accounts, and include IAM roles trusting an external account with ReadOnlyAccess in the same report.

For an enclave key named above, resolve which principals IAM already admits to those operations and report them as the set that reaches the material without presenting a measurement.

Report a grant as intentional where the evidence supports it: a VPC endpoint service whose allowed principals are all inside the organization, an SNS topic granting only `sns:Subscribe` over `https` on a topic the account documents as a public feed, or an SES identity policy naming a sending partner that also appears in the identity's authorized senders. Name the evidence. A statement naming an outside principal with no such evidence is not intentional.

Order findings by risk, most consequential first.

Call shapes a run has proven:

KMS: `X-Amz-Target: TrentService.{Operation}` on `kms.<region>.amazonaws.com`.

SQS: `X-Amz-Target: AmazonSQS.ListQueues` with a `Content-Type` of `application/x-amz-json-1.0` on `sqs.<region>.amazonaws.com`.

SES: `email.<region>.amazonaws.com`.

EventBridge Schemas: `GET /v1/policy?registryName={name}` on `schemas.<region>.amazonaws.com`.

Lambda: `GET /2015-03-31/functions` on `lambda.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.

Organizations: `X-Amz-Target: AWSOrganizationsV20161128.{Operation}` on `organizations.us-east-1.amazonaws.com`.
