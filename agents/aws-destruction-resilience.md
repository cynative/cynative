---
description: Determine what in an AWS account could be destroyed with no recoverable copy, starting with the keys already scheduled for deletion.
---

Research what in this account - RDS instances and clusters, Redshift clusters, ElastiCache Redis clusters, EBS volumes, EKS clusters and KMS keys - could be destroyed with no copy that survives the same principal.

Read which customer-managed keys are in `PendingDeletion` state and which are in `PendingReplicaDeletion` - the state a multi-Region primary key already scheduled for deletion holds for as long as any replica remains - which RDS instances and clusters have a snapshot whose `SnapshotType` is not `automated` and which carry an `AwsBackupRecoveryPointArn`, each Redshift cluster's `AutomatedSnapshotRetentionPeriod` and each ElastiCache Redis cluster's `SnapshotRetentionLimit`, and which EKS clusters have `deletionProtection` disabled. For EBS, read which volumes have no snapshot together with each volume's own attachment record. KMS, RDS, Redshift, ElastiCache, EBS and EKS are regional, so enumerate the enabled regions from the account and read once per region in that result rather than per region in a list of your own.

An `automated` snapshot is removed with the database by default, so a copy that outlives the database is one whose `SnapshotType` is `manual` or `awsbackup`. The `awsbackup` type does not apply to Aurora, so filtering a cluster's snapshots for it returns nothing even where Backup manages them; there the `AwsBackupRecoveryPointArn` on the cluster itself is what carries that fact, and it comes back on the same describe. Read `SnapshotRetentionLimit` from the replication group where the Redis cluster belongs to one and from the cache cluster otherwise.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no customer-managed key is in `PendingDeletion` or `PendingReplicaDeletion`, every RDS instance and cluster has either a snapshot whose `SnapshotType` is `manual` or `awsbackup` rather than `automated` or an `AwsBackupRecoveryPointArn`, every Redshift cluster's `AutomatedSnapshotRetentionPeriod` and every ElastiCache Redis cluster's `SnapshotRetentionLimit` is at least seven days, and every EKS cluster has `deletionProtection` enabled. Seven days is the bound because it spans a full weekly cycle, so a deletion made before a weekend is still recoverable when the week resumes. Report the regions the sweep covered and the enabled-region listing it took them from, the volumes with no snapshot as a count split by their attachment record, and the retention periods by cluster, and which of the six service enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the resources that are not clean:

For a pending key, resolve what it encrypts across EBS, RDS, S3, Secrets Manager and the other services that record a key ARN, and report the CloudTrail event that scheduled the deletion, which event lookup reaches only for the last 90 days. A key in `PendingDeletion` carries a `DeletionDate`; one in `PendingReplicaDeletion` carries only `PendingDeletionWindowInDays`, and its date is fixed when the last replica is deleted. Snapshots encrypted by a pending key remain listable and become unreadable once the key is destroyed.

For each resource that does have a copy, read the backup vault's account and region from its ARN, its `Locked` state and `MinRetentionDays` from the vault listing, and its access policy, and state whether the principals who can delete the source can also delete the copy. A snapshot in the same account under the same key deletable by the same principal is not separation.

Resolve the principals holding `eks:DeleteCluster` on each cluster without `deletionProtection`.

Resolve each snapshotless volume's attached instance and that instance's Auto Scaling group membership before reporting the volume; that resolution is a second read per volume, which is why the gate does not make it.

Report a volume with no snapshot as intentional where the evidence supports it: an attachment to an instance in an Auto Scaling group, which is replaced rather than recovered, or a non-root device whose data the account also writes to a service that is itself backed up. Name the evidence. A volume with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

EKS: `GET /clusters` on `eks.<region>.amazonaws.com`.

KMS: `X-Amz-Target: TrentService.{Operation}` on `kms.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`; the account's own snapshots at `GET /?Action=DescribeSnapshots&Owner.1=self&Version=2016-11-15`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

Redshift: `GET /?Action=DescribeClusters&Version=2012-12-01` on `redshift.<region>.amazonaws.com`.

CloudTrail: `X-Amz-Target: CloudTrail_20131101.{Operation}` on `cloudtrail.<region>.amazonaws.com`; the same target fully qualified as `com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.{Operation}`.
