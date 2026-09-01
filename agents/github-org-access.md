---
description: Determine who holds write access across a GitHub organization and how an outside identity could obtain it.
---

Research who holds write access across the repositories in this organization, and how an identity outside it could obtain that access. Take which organization that is from the credential's own organization listing rather than asking for it: the listing names the organizations the token reaches, and where it names more than one, report each of them. Take the repositories from the organization's own repository listing a few at a time, and take every repository fact the reads below need from that repository's own record rather than from that listing: a listing entry is the repository's whole record at several kilobytes each, so a page asked for a whole organization at once carries far more record than any of the reads below use.

Read the organization's `default_repository_permission`, whether two-factor authentication is required for all members, the repository creation setting together with the visibility levels it permits, the repository deletion and transfer setting, the outside collaborator list, and the installed GitHub Apps with their permission scopes and `repository_selection`. No REST call available to a user token names who installed an app or enumerates the repositories a `selected` installation covers, so `repository_selection` is the whole of what the API says about an installation's breadth.

Read what an identity outside the organization already holds from the installations above. No REST call available to a user token lists the fine-grained personal access tokens with access to organization resources or the token requests awaiting approval, since both of those answer a GitHub App alone, so the installations are the whole of what the API says about access an outside identity already holds. A personal access token and an installation token share the property that neither presents a second factor, so a two-factor requirement on members does not cover either.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if `default_repository_permission` is `read` or `none`, two-factor authentication is required, repository creation, deletion and transfer are restricted to owners, the organization holds no outside collaborators and no app holds organization-wide write: the outside-collaborator listing names who holds the role but not what any of them can write to, so it can only clear the case where the list is empty. Report the member and outside collaborator counts, the visibility levels repository creation permits, the repository deletion and transfer setting, and the installed GitHub Apps with each app's scopes and `repository_selection`, the count of repositories the enumeration covered, and which of the member, collaborator and app enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the principals and apps that are not clean:

Where the base permission is `write` or `admin`, per-repository access lists do not narrow anything, and neither does a branch rule: a rule constrains what a writer may merge rather than who holds write. What that leaves is which repositories with deployment or publishing rights every member can already write to.

Resolve which repositories each owner and administrator without two-factor authentication administers.

An outside collaborator's permission is per repository and the organization's outside-collaborator listing does not carry it: resolve each outside collaborator's permission from each repository's own collaborator list.

A transfer relocates a repository and its history to an account outside the organization, and a member who can create a public repository publishes organization code without needing one.

Compare each app's scopes against the workflows in the organization's repositories that reference it, taking the file list from a contents read on the workflow directory and each file's own content from a second contents read on its path, which is where the content is and is one call per file: an installation on every repository whose scopes nothing uses is the widest grant here.

Read team repository permissions, where a team holds write or admin on repositories its membership does not otherwise relate to.

Report an app as intentional where the evidence supports it: a GitHub-published app, scopes matching the workflows and checks the organization's repositories reference, or a `repository_selection` of a selected set rather than every repository. Name the evidence. An app installed organization-wide that no workflow references with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Repository contents: `GET /repos/{owner}/{repo}/contents/{directory}` for the file list, and `GET /repos/{owner}/{repo}/contents/{path}` for one file's content, on `api.github.com`. Either answers with or without an `Accept` of `application/vnd.github.raw+json`.

Organization settings: `GET /orgs/{org}` on `api.github.com`.

Organization membership: `GET /orgs/{org}/members`, `GET /orgs/{org}/members?role=admin`, `GET /orgs/{org}/members?filter=2fa_disabled`, `GET /orgs/{org}/outside_collaborators` and `GET /orgs/{org}/teams`, on `api.github.com`.

Installations: `GET /orgs/{org}/installations` on `api.github.com`.

Identity and organizations: `GET /user` and `GET /user/orgs` on `api.github.com`.

Organization repositories: `GET /orgs/{org}/repos?per_page=4&page={n}` on `api.github.com`.
