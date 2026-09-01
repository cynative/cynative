---
description: Find GitHub Actions workflows that run untrusted code with credentials, and resolve what those credentials reach.
---

Research which GitHub Actions workflows in this organization execute code an outsider controls while holding the repository's credentials. Take which organization that is from the credential's own organization listing rather than asking for it: the listing names the organizations the token reaches, and where it names more than one, report each of them. Take the repositories from the organization's own repository listing a few at a time, and take every repository fact the reads below need from that repository's own record rather than from that listing: a listing entry is the repository's whole record at several kilobytes each, so a page asked for a whole organization at once carries far more record than any of the reads below use.

Scan every workflow file for four things, taking the file list from the repository's own workflow listing and each file's own content from a contents read on the path that listing gives, which is where the content is and is one call per file. That listing also names the workflows GitHub generates rather than the ones the repository carries, and a generated one has no file at the path it names, so read content only for a path inside the workflow directory. First, a fork-reachable trigger combined with a checkout of untrusted code: `pull_request_target` with a `ref` of `github.event.pull_request.head.sha`, `github.event.pull_request.head.ref` or a merge ref, or `workflow_run` with a `ref` of `github.event.workflow_run.head_sha` or `github.event.workflow_run.head_branch`. Second, an attacker-controlled expression interpolated into a `run` block, where it is substituted before the shell parses the command - `github.event.pull_request.title`, `github.event.pull_request.body` and `github.head_ref` under `pull_request_target`, and `github.event.issue.title` or `github.event.comment.body` under the `issues` and `issue_comment` triggers, which are fork-reachable in their own right because anyone who can open an issue or comment can set them. Third, an action published outside this organization and outside the `actions` and `github` namespaces referenced by anything other than a commit SHA. Fourth, a job targeting a self-hosted runner. All four are properties of the same file text, so evaluate them on the same pass that fetches it, because a separate pass per condition costs the whole enumeration again. The first two are defined on the triggers they name, so a workflow whose own triggers are none of `pull_request_target`, `workflow_run`, `issues` or `issue_comment` cannot meet either: take the trigger set from the file text first and judge those two over the workflows that carry one of those triggers, while the remaining two are judged over every workflow.

Read whether the repository accepts pull requests from forks, and read the secret scanning, push protection and immutable release states per repository. Read the immutable release state from one release rather than from a repository's whole release history: the setting governs releases made after it is turned on, so one release published since carries it, and a release entry runs to tens of kilobytes. Immutable releases belong with the rest: a mutable release can be republished under the same name after the review that approved it, which is the same failure as an action pinned to a tag rather than a SHA - what runs is not what was approved.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no workflow combines a fork-reachable trigger with a checkout of untrusted code, no attacker-controlled expression appears inside a `run` step, every action published outside this organization and outside the `actions` and `github` namespaces is pinned to a SHA, no self-hosted runner is registered to a repository that accepts pull requests from forks, secret scanning and push protection are enabled on every repository, and no repository publishes releases without immutable releases enabled. Report the workflow count split by which of the fork-reachable triggers named above each uses, the checkout steps naming an untrusted ref as a count, the count of `run` steps interpolating one of the attacker-controlled expressions named above, the secret scanning, push protection and immutable release states as counts of repositories in each state, the count of repositories the enumeration covered, and which of the workflow, action and runner enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the workflows that are not clean:

Trace each one from the trigger an outsider reaches to what the job holds when it runs, at the file and line where it happens. The secrets are the ones the workflow file itself references, since the organization's own Actions secret and variable inventory needs an administrator and the ceiling does not reach it.

Read the `permissions` block and the repository's default token permission and any `id-token: write` with the cloud role the workflow assumes. Where the cloud connector cannot resolve the role, the role name alone is the answer. Resolve it against the account's own authorization details for roles, which return every role with its trust policy and its attached policies in one answer rather than needing a read per name: a role the workflow names and the account does not hold is absent from that answer rather than a read that did not answer.

A self-hosted runner on a repository that accepts fork pull requests carries state between jobs, so what one job leaves behind the next one finds.

Secret scanning or push protection disabled is the detection state for a finding here, and a repository publishing releases without immutable releases belongs against the workflow that publishes them.

Report an unpinned action as intentional where the evidence supports it: an action published by this organization, or one in the `actions` or `github` namespace. Name the evidence. A tag-referenced action from outside those namespaces with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Repository contents: `GET /repos/{owner}/{repo}/contents/{directory}` for the file list, and `GET /repos/{owner}/{repo}/contents/{path}` for one file's content, on `api.github.com`. Either answers with or without an `Accept` of `application/vnd.github.raw+json`.

Workflows and runners: `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/actions/runners`, `GET /repos/{owner}/{repo}/actions/permissions` and `GET /repos/{owner}/{repo}/actions/permissions/workflow`, on `api.github.com`.

Release state: `GET /repos/{owner}/{repo}/releases?per_page=1` on `api.github.com`.

Identity and organizations: `GET /user` and `GET /user/orgs` on `api.github.com`.

Organization repositories: `GET /orgs/{org}/repos?per_page=4&page={n}` on `api.github.com`.

IAM: `GET /?Action=GetAccountAuthorizationDetails&Filter.member.1=Role&Version=2010-05-08` and `GET /?Action={Operation}&Version=2010-05-08`, on `iam.amazonaws.com`.
