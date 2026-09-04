---
description: Find AWS DNS records and resource references whose target no longer exists in the account, and registered domains without transfer lock.
---

Research which Route 53 records, CloudFront origins and service-referenced bucket names in this account point at a target that no longer exists, and which registered domains can be transferred out.

Resolve every hosted zone record's target against the account's own resources. For an A record, resolve the address against the allocated Elastic IPs and against the public addresses currently assigned to running instances, load balancers and NAT gateways, since an auto-assigned public address belongs to the account without ever being an Elastic IP and reporting it as dangling on that basis is the largest false positive available here. An address that matches none of the account's own inventories is unresolved rather than dangling on that basis alone: the match only tells you whether this account currently holds the address, not whether some other operator does, so its absence from these inventories does not by itself establish that the target no longer exists or can be claimed. For aliases and CNAMEs, resolve the named CloudFront distribution or load balancer. An alias target from another family Route 53 supports is unresolved rather than dangling: this sweep not resolving it says nothing about whether the target still exists. Read CloudFront distributions for S3 origins as well. Read which accounts this organization holds, because that is what places an account inside it or outside. The Elastic IPs, instances, load balancers and NAT gateways a target resolves against are regional, so enumerate the enabled regions from the account and resolve against the result of reading each of those once per region in that result rather than per region in a list of your own.

For a CNAME or alias to an S3 website endpoint, and for the bucket names the account's own service configurations reference, bucket existence is only partly decidable: a bare status code settles nothing, since S3 documents 400, 403 and 404 alike for a bucket that does not exist and for one the caller cannot reach, so probe with a request that answers with a body and read the error code it carries. Treat a 404 carrying `NoSuchBucket` as absent, and treat a 403 as the name beyond this credential's reach with its existence and its owner both unresolved, since a bucket in this account answers the same way where the credential cannot read it or a policy denies it, and a denied caller can be answered 403 for a name no account holds. Record which response you got with the name.

Read the transfer lock state, the expiry date and the auto-renew setting on every registered domain. A registered-domain read that did not reach the Route 53 Domains API leaves the lock state unread, and must not be reported as every domain being locked.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every record target resolves to a resource in the account or the organization, no bucket name the account's own service configurations reference answered `NoSuchBucket`, and every registered domain has transfer lock enabled. Report the regions the sweep covered and the enabled-region listing it took them from, the hosted zone record count by type with the alias and CNAME targets that resolved, the counts of targets that resolved against the Elastic IPs, with the count of Elastic IPs allocated in the account beside it since a target matching none of them and the account holding none are different answers, and against the public addresses assigned to instances, load balancers and NAT gateways, the CloudFront distribution count with their S3 origins, the S3 website endpoint CNAMEs and aliases and the bucket names the account's own service configurations reference with the response each of those names answered and whether that response settles the bucket's existence, and the registered domains `route53domains:ListDomains` returned with their transfer lock state, expiry date and auto-renew setting, the count of accounts the organization holds, stated as this account being in no organization where that is the answer, and which of the hosted zone, address, distribution, bucket and registered domain enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the records that are not clean:

Report each with its position in the zone. A name under the same registrable domain as the application can share that domain's cookie scope, but only where the application's own `Set-Cookie` response shows a `Domain` attribute at that scope or host-only behavior; the parent domain's records establish neither, so mark the cookie-scope impact unresolved.

Resolve targets against the organization's account list where the API allows it, since a record may point at a resource in another account the organization owns. Where it does not, report the record as unresolved rather than as dangling.

For the shadow resource pattern, report only bucket names that the account's own service configurations reference and that answered a 404 carrying `NoSuchBucket`. Do not enumerate candidate names, and do not report a 403 as a takeover opportunity; report that name as unresolved, since the code settles neither that the bucket exists nor that it does not.

Report registered domains without transfer lock with their expiry date and auto-renew setting, and note which of them a hosted zone in this account serves.

Report a record as intentional where the evidence supports it: a target that is a third-party service the account also references in a configuration you can read, a CloudFront alternate domain name, or an ACM or SES validation record. Name the evidence. A record whose target resolves to nothing with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Route 53 Domains: `route53domains.us-east-1.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

Organizations: `X-Amz-Target: AWSOrganizationsV20161128.{Operation}` on `organizations.us-east-1.amazonaws.com`.
