---
description: Determine which GitHub repositories permit a merge without effective review, and which of those deploy or publish.
---

Research which repositories in this organization permit a change to reach the default branch without effective review, and which of those deploy or publish anything. Take which organization that is from the credential's own organization listing rather than asking for it: the listing names the organizations the token reaches, and where it names more than one, report each of them. Take the repositories from the organization's own repository listing a few at a time, and take every repository fact the reads below need from that repository's own record rather than from that listing: a listing entry is the repository's whole record at several kilobytes each, so a page asked for a whole organization at once carries far more record than any of the reads below use.

The rules in force on a repository's default branch come from the branch rules listing, which returns them in one answer with the source of each. Take from it whether any rule is in force, `enforce_admins`, the required approval count, `dismiss_stale_reviews`, the required status check contexts, the code owner review requirement, the force push and deletion permissions, and the signed commit requirement. Take the archived flag and the pushed-at date from the repository's own record, and take the bypass actor list from the ruleset's own definition at the ruleset id that listing names.

Read which of those rules came from above the repository off the source type, the source and the ruleset id that same listing carries on every rule it returns, because a rule sourced above the repository applies to the default branch of every repository it names and a rule set resolved from the repository alone over-reports by exactly the repositories one covers. Every rule that listing returns is in force together and the most restrictive outcome wins. A ruleset's bypass actors bypass that ruleset and nothing else, so they do not weaken a rule another source puts in place. That listing is the whole of what is in force on a branch: where it returns nothing, nothing is in force, and that is the answer rather than a read to go and repeat against another path.

Whether a required status check context still matches a job the repository's workflows produce means parsing every workflow file in every repository, which costs what the second stage costs. Read the contexts here as strings and compare them to job names only after the condition below.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every default branch on a repository that is not archived carries a rule from that listing with at least one required approval, `enforce_admins` true, no bypass actor able to reach that rule, and the force push and deletion permissions both disabled. Report the repository count with the archived repositories and their pushed-at dates, whether any rule is in force on each default branch, with the source type, the source and the ruleset id on the rules in force there and the repositories each source reaches, the `enforce_admins` and `dismiss_stale_reviews` states as counts, the bypass actors by name per repository, the required status check contexts per repository as strings, unmatched at this stage against the workflow files that would produce them, and the signed commit requirement and code owner review requirement as counts, and which of the repository, rule and ruleset reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the repositories that are not clean:

Establish whether the repository matters. Read its workflow files for deployment jobs and cloud OIDC role assumptions, taking the file list from a contents read on the workflow directory and each file's own content from a second contents read on its path, which is where the content is and is one call per file; read whether it publishes releases, take whether it publishes packages from those same workflow files, since the organization's own package listing needs a scope the ceiling does not reach, and read its contributor count.

Resolve the repository administrator list where `enforce_admins` is false: that list and the bypass actors together decide who can merge past the rule.

Compare the required status check contexts against the job names the repository's workflows produce and report the contexts that no longer run: a required check that never reports blocks the merge rather than satisfying the requirement, so name it as a stalled check rather than a bypass.

A rule requiring code owner review is what makes the CODEOWNERS file worth resolving, and where a repository carries no such rule there is nothing to resolve and the requirement is already reported in the count above. Where one does, resolve the file from a contents listing of the repository root and of its `.github` and `docs` directories, and report the requirement as ineffective only where the file is absent, unparseable or covers no path that receives commits.

Report an unprotected repository as intentional where the evidence supports it: an archived repository, or a repository with a single contributor and no workflow. Name the evidence. An unprotected default branch with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Repository contents: `GET /repos/{owner}/{repo}/contents/{directory}` for the file list, and `GET /repos/{owner}/{repo}/contents/{path}` for one file's content, on `api.github.com`. Either answers with or without an `Accept` of `application/vnd.github.raw+json`.

Branch rules: `GET /repos/{owner}/{repo}/rules/branches/{branch}` returns the rules in force on a branch, each carrying the source type, the source and the ruleset id that put it there; `GET /repos/{owner}/{repo}/rulesets` names the rulesets on a repository by id, and `GET /repos/{owner}/{repo}/rulesets/{ruleset_id}` returns one ruleset's own definition with its rules and its bypass actors. All on `api.github.com`.

Repository state: `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/contributors` and `GET /repos/{owner}/{repo}/releases?per_page=1`, on `api.github.com`.

Repository administrators: `GET /repos/{owner}/{repo}/collaborators?permission=admin` on `api.github.com`.

Identity and organizations: `GET /user` and `GET /user/orgs` on `api.github.com`.

Organization repositories: `GET /orgs/{org}/repos?per_page=4&page={n}` on `api.github.com`.
