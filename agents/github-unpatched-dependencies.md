---
description: Find dependencies with a known advisory still shipping from this organization's repositories, and which of them a fix already exists for.
---

Research which dependencies with a known advisory are still shipping from the repositories in this organization, and which of those a fix already exists for. Take which organization that is from the credential's own organization listing rather than asking for it: the listing names the organizations the token reaches, and where it names more than one, report each of them. Take the repositories from the organization's own repository listing a few at a time, and take every repository fact the reads below need from that repository's own record rather than from that listing: a listing entry is the repository's whole record at several kilobytes each, so a page asked for a whole organization at once carries far more record than any of the reads below use.

Read every repository's Dependabot security update status and its Dependabot alerts. The status shows whether GitHub raises an automatic fix, not whether the repository is scanned, so report it as its own fact. Where the alert read itself comes back denied, that repository holds no visible alert rather than no vulnerability: a denied read shows only that the alerts are not visible to this credential, not that no scanner runs, so report the alert state as unresolved rather than clean, and a repository whose alerts cannot be read is the one a reader should look at first.

Take the alerts one at a time from the repository's own alert listing: a single alert entry carries the whole advisory, and the largest of them run to tens of kilobytes on their own, so a page of several is many times the size of the fields below. Read on each alert whether it is open, the advisory's severity, whether the dependency is a runtime or a development one, whether it is direct or transitive, the manifest it is declared in, the first version patched against the advisory, the age of the alert, and the reason recorded where one was dismissed.

The first patched version is what separates the two findings this agent produces. An alert carrying one is a fix somebody has already published and the repository has not taken, which is a question about how quickly this organization applies them. An alert carrying none is a dependency with no fix to take, which is a question about whether the repository can drop it or must accept the risk, and no amount of patching cadence answers it.

An alert already dismissed with a reason recorded is a decision somebody made rather than a finding waiting to be made, so report those as the triage that has happened and count them apart from the open ones. An alert dismissed with no reason recorded is not a decision anybody can audit.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if every repository has Dependabot security updates enabled and holds no open alert. Report the count of repositories with the status enabled and disabled, the open alert count per repository split by the advisory severity, the count of open alerts a first patched version exists for and the count with none, the count of open alerts against a runtime dependency and against a development one, the direct and transitive counts, the manifests the open alerts are declared in, the age of the oldest open alert and the median age, the dismissed count with the reasons recorded and the count of those dismissed with no reason recorded, and the count of repositories the enumeration covered, and which of the status and alert reads above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the alerts that are not clean:

Name each alert by its advisory identifiers, its package and ecosystem, and the version range the advisory covers.

A transitive dependency is fixed by moving the direct one that pulls it in, so the transitive package named alone leaves the reader nothing to do.

An advisory against a manifest the default branch does not carry, or a lockfile no build resolves, is a finding about the file rather than about the dependency.

Report an open alert as intentional where the evidence supports it: a development-scoped dependency in a repository that publishes nothing, or an advisory whose vulnerable version range the declared version already sits outside. Name the evidence. An open alert against a runtime dependency with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Dependabot alerts: `GET /repos/{owner}/{repo}/dependabot/alerts?per_page=1&after={cursor}` on `api.github.com`, whose alert objects carry the advisory, the dependency with its manifest and scope, the vulnerable version range and the first patched version.

Repository state: `GET /repos/{owner}/{repo}` on `api.github.com`, which carries the Dependabot security update status.

Identity and organizations: `GET /user` and `GET /user/orgs` on `api.github.com`.

Organization repositories: `GET /orgs/{org}/repos?per_page=4&page={n}` on `api.github.com`.
