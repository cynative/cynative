---
description: Map the paths from each AWS IAM principal to administrative control, naming the calls that walk each one.
---

Research which IAM users, roles and groups in this account can reach administrative control, and which API calls walk each path.

Take the principals with their inline and attached policy from the account authorization details filtered to users, roles, groups and customer-managed policies, then read each attached AWS-managed policy once rather than the whole catalogue, except the ones only a service-linked role carries, which AWS publishes under `aws-service-role` and which stay in the count: AWS creates that role for one of its own services, no principal in this account can assume it, and the account cannot change either fact, so nothing the policy grants is a path anyone here can walk. The same response carries each principal's permission boundary, which caps whatever its policies grant however they are written, so take it here rather than looking for it a second time. Unfiltered, the same call also returns every AWS-managed policy AWS publishes, which is megabytes of policy this account has nothing attached to and enough of a response that the run ends before it has read anything at all.

Scan every attached AWS-managed policy, attached customer-managed policy and inline policy for two things: a direct grant of `Action: "*"` on `Resource: "*"` or AdministratorAccess, and the presence of any escalation permission - `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:AttachGroupPolicy`, `iam:PutRolePolicy`, `iam:PutUserPolicy`, `iam:PutGroupPolicy`, `iam:AddUserToGroup`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` on `Resource: "*"`, `lambda:UpdateFunctionCode`, or `cloudtrail:*`.

`iam:PassRole` is a path only together with a service that executes code, so take the code-executing actions in the same pass. `ec2:RunInstances` and `cloudformation:CreateStack` run the code in the call that passes the role. `lambda:CreateFunction`, `ecs:RegisterTaskDefinition`, `glue:CreateJob` and `codebuild:CreateProject` only define what will run, so each completes a path only with the action that starts it - `lambda:InvokeFunction`, `ecs:RunTask`, `glue:StartJobRun` and `codebuild:StartBuild` respectively. `cloudtrail:*` is not a route to administrative control; it removes the record of one, so it is carried here as an anti-forensics companion to the paths below rather than as a path. Whether the deletion of a trail would itself raise an alert is outside this agent's scope.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no policy carries a direct grant of `Action: "*"` on `Resource: "*"` or AdministratorAccess, no policy pairs `iam:PassRole` with one of the code-executing actions named above on the same principal, and no policy carries any of the other escalation permissions named above. `iam:PassRole` on its own is present in most accounts and is not a path without the paired action. Report the principal count split into users, roles and groups, with the filtered account authorization details as the call that served them; the policy count split into attached AWS-managed, attached customer-managed and inline, with the AWS-managed policies only a service-linked role carries counted apart; the count of principals carrying a permission boundary, stated as none carrying one where that is the answer rather than left silent; the count of principals holding each of the escalation permissions named above; and the count holding `iam:PassRole` with none of the code-executing actions named above, and which of the principal, policy and organization reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the principals that hold one of them:

Resolve the effective permission set - group membership and permission boundaries - then expand each escalation permission into a path and name the principal at its start.

Read the service control policies in force on this account in the same pass - the policies `organizations:ListPoliciesForTarget` returns for this account and for each parent above it up to the root, walked with `organizations:ListParents`, rather than the organization's whole policy inventory, which lists policies attached to organizational units this account does not sit under - and report which of the paths below they deny. A path the organization already blocks is not one this account can walk, and an account outside an organization has no such policy at all, which is a different fact from having one that denies nothing.

- `iam:PassRole` with a code-executing action: expand the PassRole resource pattern against the account's roles and name which of the matched roles are administrative, discounting any whose trust policy does not admit the executing service.
- The IAM write actions are each a single-call escalation except `iam:UpdateAssumeRolePolicy`, which rewrites a role's trust and then needs `sts:AssumeRole` to use it; report the target the caller can reach. `iam:CreateLoginProfile` and `iam:UpdateLoginProfile` give an existing user an interactive credential, `iam:AddUserToGroup` gives one user whatever the group already grants, and `iam:AttachGroupPolicy` and `iam:PutGroupPolicy` change what the group grants and so reach every current and future member.
- `sts:AssumeRole` on `Resource: "*"` expands against the roles whose trust policy the principal can satisfy.
- `lambda:UpdateFunctionCode` matters on a function whose execution role is more privileged than the caller.
- `cloudtrail:*` permits deleting or stopping the trails that would record the rest; report it against the principals that already hold one of the paths above.

Name the principals inside each escalation-permission count above and leave out of it the ones already reported as holding a direct administrative grant, since `Action: "*"` carries every permission on that list at once: counting one administrator against seventeen actions reports how many administrators the account has and nothing about who else can reach them.

Where a role's trust admits a federated identity provider and carries no condition naming which identities it admits, report the path with that bound named rather than as intentional: who holds it is decided in the provider's own assignment, which IAM does not carry and this agent cannot settle. That is a different report from a path nothing bounds at all, and a different one again from a trust whose condition names the identity.

Rank by what the path reaches: a path ending at a direct administrative grant first, then one ending at a role that can pass or assume an administrative role, then one reaching a single service's data, and name the terminal principal in each case.

Report a path as intentional where the evidence supports it: a principal that is a deployment or automation role, a trust policy whose condition names the identities it admits rather than the provider that vouches for them - a repository and reference carried on a CI provider's token, a named external account or role - or a permission set matching what the principal deploys. Name the evidence. A path from a principal with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.

Organizations: `X-Amz-Target: AWSOrganizationsV20161128.{Operation}` on `organizations.us-east-1.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.
