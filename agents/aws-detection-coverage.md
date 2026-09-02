---
description: Find the AWS regions and alarm paths where activity would generate no signal that reaches anyone.
---

Research which of this account's enabled regions have no GuardDuty detector, no Security Hub and no CloudTrail coverage, and which CloudWatch alarms deliver to nothing.

Enumerate the enabled regions from the account and iterate exactly that result rather than a list of region names of your own, since which regions are enabled is a property of the account and a listing asked for every region instead returns the ones it has not opted into, which answer nothing. Then per region take whether GuardDuty has an enabled detector and the state of its S3 protection, EKS audit log monitoring, Lambda protection, RDS protection and EC2 malware protection features; whether Security Hub is enabled with at least one standard or integration, taking the enablement from `securityhub:DescribeHub`, the standards from `securityhub:GetEnabledStandards` and the integrations from `securityhub:ListEnabledProductsForImport`; whether a trail logs that region and whether that trail is multi-region; and the count of open GuardDuty findings at high or critical severity, taken from `GetFindingsStatistics` as `CountBySeverity` rather than by counting a findings listing, which returns at most fifty per page and would report fifty on any region holding more.

Read every CloudWatch alarm's `ActionsEnabled` flag, its configured ALARM-state actions and each action's resolved target, including whether an SNS topic target carries a confirmed subscription. Read the organization's delegated administrator for GuardDuty, Security Hub and AWS Config, the auto-enable setting for GuardDuty and Security Hub, and the Config aggregator's region list, and read whether a service control policy in force on this account denies operations in each region - the policies `organizations:ListPoliciesForTarget` returns for this account and for each parent above it up to the root, walked with `organizations:ListParents`, rather than the organization's whole policy inventory, which lists policies attached to organizational units this account does not sit under - since a denied region is not a gap.

Coverage and detection are different questions. An open finding is something the detection stack already saw, so it does not belong in the condition that decides whether the detection stack exists.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every enabled and undenied region carries an enabled detector, a Security Hub with at least one standard or integration, and coverage from a trail, and every CloudWatch alarm has `ActionsEnabled` true with an action configured for the ALARM state that resolves to an existing target and, where that target is an SNS topic, carries a confirmed subscription. Report the region coverage table with the multi-region trail state and the Security Hub enablement `securityhub:DescribeHub`, `securityhub:GetEnabledStandards` and `securityhub:ListEnabledProductsForImport` returned, the per-region GuardDuty feature state for S3 protection, EKS audit log monitoring, Lambda protection, RDS protection and EC2 malware protection as counts, the delegated administrator for GuardDuty, Security Hub and AWS Config with the auto-enable setting for GuardDuty and Security Hub and the Config aggregator's region list, the service control policy region denials with `organizations:ListPoliciesForTarget` and `organizations:ListParents` as the calls that served them, and the count of open high and critical GuardDuty findings taken from `GetFindingsStatistics` as `CountBySeverity`, and which of the per-region and organization reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the regions and alarms that are not clean:

Report open high and critical GuardDuty findings ahead of every configuration gap, with the affected resource and the permissions attached to it.

For each uncovered region, name which of the three services is missing and expand the GuardDuty feature gaps in full, stating for each disabled feature which resource type in that region is consequently unwatched.

Resolve each remaining alarm's action ARN to its target and report the alarms that terminate, including actions naming an SNS topic with no confirmed subscriptions.

Where the organization has no delegated administrator or no auto-enable for a service, report the member accounts that would therefore onboard without it.

Report an uncovered region as intentional where the evidence supports it: a service control policy above the account denying every operation in that region, or an absence of every one of the per-region reads above in it - no detector, no Security Hub, no trail covering it, no aggregator and no alarm - in a region where at least one other enabled region carries that coverage. An account carrying none of it anywhere is an uncovered account rather than a set of unused regions, and the second piece of evidence does not reach that case. Neither is an inventory of what the region holds, which this agent does not read. Name the evidence. A region carrying resources with no such evidence is not intentional.

Order findings by risk, most consequential first.

Call shapes a run has proven:

CloudWatch: `X-Amz-Target: GraniteServiceVersion20100801.DescribeAlarms` with a `Content-Type` of `application/x-amz-json-1.0` on `monitoring.<region>.amazonaws.com`.

AWS Config: `X-Amz-Target: StarlingDoveService.DescribeConfigurationAggregators` on `config.<region>.amazonaws.com`.

Security Hub: `securityhub:DescribeHub` answers at `GET /accounts` on `securityhub.<region>.amazonaws.com`; `securityhub:ListOrganizationAdminAccounts` at `GET /organization/admin`; `securityhub:GetEnabledStandards` at `POST /standards/get`; `securityhub:ListEnabledProductsForImport` at `GET /productSubscriptions`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

Organizations: `X-Amz-Target: AWSOrganizationsV20161128.{Operation}` on `organizations.us-east-1.amazonaws.com`.

CloudTrail: `X-Amz-Target: CloudTrail_20131101.{Operation}` on `cloudtrail.<region>.amazonaws.com`; the same target fully qualified as `com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.{Operation}`.
