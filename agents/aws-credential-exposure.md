---
description: Assess AWS root credentials, IAM user MFA state and long-lived access keys against what each one reaches.
---

Research whether the root account or any IAM user in this account holds a credential that is usable as a way in, and how far each one reaches.

Read the account credential report and take, per user, the console password state, the MFA device state, and each access key's creation date, last-used date, last-used service and last-used region. Read the root account's MFA device state and its access key state from the same report. The report records MFA only as active or not, so read the account's assigned virtual MFA devices as well; active MFA on a principal that holds none of them is hardware. Read which users have `AdministratorAccess` attached directly by listing the entities that one policy is attached to, which is a single call against its ARN rather than an expansion of every principal's permissions or a dump of the account's whole policy inventory, and read the membership of each group that call names to find who holds it through one.

Root activity means the credential report's `password_last_used`, `access_key_1_last_used_date` and `access_key_2_last_used_date` fields within the last 90 days, which is the furthest back a trail lookup reaches, not a trail query. Read the organization's centralized root credentials management setting as well, which `iam:ListOrganizationsFeatures` returns as the features the organization has enabled; an account outside an organization has no such setting, which is a different fact from having it disabled and is the answer that call gives back for one.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if the root account has no access key, has a hardware MFA device and shows no console or key use in the window, every user with a console password has an MFA device, and every user with `AdministratorAccess` attached has one too. Report the user count, the console password count, the MFA device count split by type into virtual and hardware against the account's assigned virtual MFA devices, the `AdministratorAccess` attachment count and the membership count of each group that call names, the access key creation dates and ages with their last-used dates, services and regions as counts, and the organization's centralized root credentials management state or its absence, and which of the credential report, virtual MFA device, policy attachment and `iam:ListOrganizationsFeatures` reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the credentials that are not clean:

Report an active root access key first with its creation date and last-used service and region, then root console or key use within the window, with the CloudTrail events for that session and the resources they touched.

Resolve each affected user's effective permissions and report the credential together with what it reaches. Keep users with a virtual MFA device apart from users with none, and treat a user with access keys and no console password as having no interactive path rather than as a console risk.

Where centralized root credentials management is disabled, report which member accounts can still recover their own root credential. Where the account is outside an organization, report that the control does not apply rather than reporting it as a gap.

Report separately any key whose last-used region is one no other key in the credential report was used in, which is the comparison that report already supports and costs no further call; a region holding no resource is a different question and belongs to another agent. Keys never used since creation belong in a count.

Report a long-lived access key as intentional where the evidence supports it: a principal whose name and permissions match a single service, a last-used service matching that permission set, or the absence of any console password on the same user. Name the evidence. A key on a principal with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.

CloudTrail: `X-Amz-Target: CloudTrail_20131101.{Operation}` on `cloudtrail.<region>.amazonaws.com`; the same target fully qualified as `com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.{Operation}`.
