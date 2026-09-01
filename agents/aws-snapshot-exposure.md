---
description: Determine which AWS snapshots, AMIs and SSM documents are shared outside the account, whether the share is usable and what the source held.
---

Research which EBS snapshots, self-owned AMIs, RDS snapshots, Neptune and DocumentDB cluster snapshots and SSM documents in this account are shared outside it, and whether the share can actually be used.

Read the sharing attribute on each, separating `all` from a named account list, and read the creation date alongside it. Neptune and DocumentDB cluster snapshots come back from the same `rds:DescribeDBClusterSnapshots` enumeration as the RDS ones, told apart by `Engine`, rather than from an enumeration of their own. No sharing API on any of these five types returns when the share was made, so the creation date is the only date available and the age of a share is not a fact to go looking for. Read which accounts this organization holds, because that is what places an account inside it or outside.

Read the EBS snapshot block-public-access setting per region rather than once for the account, taking the regions from the account's own listing of enabled regions rather than from a list of your own. It is a regional setting with three modes, so a single read describes one region only and reporting it as an account-wide fact is wrong wherever the account operates in more than one.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if nothing is shared with `all` or with an account outside the organization. The EBS snapshot block-public-access setting ships unblocked in every region of every account, so a condition asserting it cannot be satisfied by an account holding no snapshot at all, and its mode per region is counted below instead. Report the sharing attribute counts by resource type, split into `all`, a named account list and unshared, with the creation dates and with `Engine` naming which cluster snapshot counts are Neptune, which DocumentDB and which RDS, and the EBS snapshot block-public-access mode per region, the count of accounts the organization holds, stated as this account being in no organization where that is the answer, and which of the resource type enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the artifacts that are not clean:

Read the KMS key policy alongside the share attribute. A shared encrypted snapshot whose key policy does not grant the target account cannot be restored by it, so classify on both facts rather than the share alone.

Trace each shared artifact to its source volume, instance or cluster where the API records it, and report that source with the IAM role it ran with. A root volume snapshot carries the instance profile credential cache and the user data.

Name the regions from the count above where the block-public-access mode is not the one blocking all sharing, and state which of the two remaining modes is set, since that decides whether a future snapshot can be made public without another control changing.

Report a public AMI or document as intentional where the evidence supports it: a product code or marketplace association on the image, other public AMIs owned by the account under a consistent name pattern, or an SSM document whose content matches an automation runbook the account publishes. Name the evidence. A public artifact with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Neptune and DocumentDB: the RDS API on `rds.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`; the account's own snapshots at `GET /?Action=DescribeSnapshots&Owner.1=self&Version=2016-11-15`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

Organizations: `X-Amz-Target: AWSOrganizationsV20161128.{Operation}` on `organizations.us-east-1.amazonaws.com`.
