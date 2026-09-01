---
description: Find the CodeBuild, CodeArtifact, Lambda layer and CDK paths that admit code or a build trigger from outside an AWS account, and resolve what each build role reaches.
---

Research which CodeBuild projects, CodeArtifact repositories, Lambda layer references and CDK bootstrap roles in this account admit code or a build trigger from outside it, and what the role behind each path reaches.

Read each CodeBuild project's webhook filter groups with their patterns and event types, whether its webhook's pull request build policy sets `requiresCommentApproval`, its source provider and the organization or account that owns the source repository, its project visibility and its service role ARN. Read each CodeArtifact repository's resource policy and each domain's permissions policy for the principals they admit, taking the repositories from `codeartifact:ListRepositories`, which returns every repository in the account with the domain that holds it and needs no domain enumeration ahead of it, and the owner account in the ARN of every Lambda layer version a function references. CodeArtifact does not answer in every enabled region, so a region where it has no endpoint holds no repository rather than an unread one: name those regions among the ones the enumeration covered rather than reporting the fields as unresolved there. Read which accounts this organization holds, because that is what places an account inside it or outside.

Read the CDK bootstrap version as the `BootstrapVersion` output of the `CDKToolkit` stack, taking that stack from the account's own stack listing rather than asking for it by name: an account that never bootstrapped CDK has no such stack, and a listing answers that with an absence where a lookup by name answers with an error. Where no stack carries that output CDK is not bootstrapped here rather than out of date. Treat 21 as the threshold because it is the first template version that bounds the file publishing role's staging bucket access to buckets this account owns.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every webhook filter pattern other than an `EVENT` filter's event list is anchored with `^` and `$`, no project has public visibility, every Lambda layer owner account is inside the organization, and the bootstrap version is either absent or at 21 or above. Report the project count with each project's service role ARN, source provider, source organization and webhook filter groups with their event types and the `requiresCommentApproval` its pull request build policy sets; the CodeArtifact repository count with the domain holding each and the principals each repository resource policy and its domain's permissions policy admit, naming those outside this account rather than counting them; the Lambda layer versions referenced as a count with the functions referencing each and the owner account in each layer ARN; and the `BootstrapVersion` output of the `CDKToolkit` stack, the count of accounts the organization holds, stated as this account being in no organization where that is the answer, and which of the project, repository, layer and stack enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the paths that are not clean:

For each unanchored pattern, state the reference or identity that would satisfy it - a `HEAD_REF` pattern of `refs/heads/main` matches `refs/heads/mainline`, an `ACTOR_ACCOUNT_ID` pattern matches any account ID that contains it - and report it with the event types in its filter group. A group including `PULL_REQUEST_CREATED` on a public source repository accepts events from anyone who can open a pull request, unless its pull request build policy sets `requiresCommentApproval` to `ALL_PULL_REQUESTS` or `FORK_PULL_REQUESTS`.

Resolve the project's service role permissions and report them with each webhook finding, since a role that can assume another role, read Secrets Manager or write to a deployment bucket is what a filter match reaches. Report public-visibility projects with the same role resolution, which bounds what the exposed build logs and artifacts contain.

Report projects whose source organization is one no other project in the account builds from, since the webhook filters are the only thing standing between that organization and the service role.

Report the principals outside this account that a repository resource policy admits, since publishing rights into a repository this account builds from are a path into the account, and report the principals outside this account that a domain's permissions policy admits, since a repository grant reaches only where the domain also grants that principal `codeartifact:GetAuthorizationToken`, and a domain grant reaches every repository the domain holds rather than the one whose resource policy names it. Report the functions and execution roles behind each out-of-organization layer.

Where the bootstrap version is below 21, read the `cdk-*-deploy-role` and `cdk-*-file-publishing-role` trust policies and report the principals they admit and the conditions that bound them, rather than assuming a particular defect from the version alone.

Report a cross-account layer or a public project as intentional where the evidence supports it: a layer owner account that AWS itself publishes layers from or that another resource in this account also references, a layer ARN following that publisher's naming, or a public project whose source repository is public and whose service role reaches nothing beyond the build's own artifact bucket. Name the evidence. A layer or project with no such evidence is not intentional.

Order findings by risk, most consequential first.

Call shapes a run has proven:

CloudFormation: `GET /?Action={Operation}&Version=2010-05-15` on `cloudformation.<region>.amazonaws.com`.

CodeArtifact: `POST /v1/repositories` on `codeartifact.<region>.amazonaws.com`.

Lambda: `GET /2015-03-31/functions` on `lambda.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.

Organizations: `X-Amz-Target: AWSOrganizationsV20161128.{Operation}` on `organizations.us-east-1.amazonaws.com`.
