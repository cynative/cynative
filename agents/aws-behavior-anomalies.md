---
description: Find the CloudTrail escalation and enumeration sequences that depart from what the principal running them normally does, and explain what changed.
---

Research whether any principal in this account ran an enumeration sweep or a privilege-escalation sequence that departs from what that principal normally does.

Confirm first which regions and time windows the account's CloudTrail event history actually covers, because that bounds everything below; `LookupEvents` reads that region's event history directly and no configured trail widens or narrows it. This agent reads two windows and `LookupEvents` is the call that returns the records for both. Detection reads the last 2 days, which is one nightly run plus one day of tolerance for a missed one. The baseline in the second stage reads the last 30 days, which is a third of what `LookupEvents` documents a region's events can be looked up over and is long enough for a weekly and a monthly job to have run inside it. Hold every run to those same two windows so two runs of this agent are comparable. A region or time window the event history does not cover is not an absence of activity.

Then query that history over the detection window by event name for the escalation events `AttachUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `CreateAccessKey` and `UpdateAssumeRolePolicy`, and query it once more for the read-only events, whose distinct names per principal are the breadth a sweep shows up as. `AssumeRole` is too common to query this way; it becomes a signal only against a baseline, so leave it to the second stage.

Four things bound what those queries return, and each of them comes back as an empty result that reads as a quiet account. A lookup takes one attribute per call, so every event name above is a lookup of its own and the read-only sweep is another. A lookup answers for one region at a time, and a multi-region trail does not change that - an event recorded in a region is retrievable only by calling against that region - so enumerate the enabled regions from the account and call once per region in that result rather than per region in a list of your own, and name any region you could not reach. Every escalation event named above is an IAM API call, and IAM is a global service whose events are recorded in `us-east-1` rather than in the region the caller used, so look those seven up in `us-east-1` alone and name it as the region that served them; the read-only sweep is not an IAM call and still answers per region. A response carries at most 50 events with a token for the next page, and the read-only sweep is by far the largest of these. Follow that token to exhaustion where the output is a count, as the escalation events are, because a count a short read produced is wrong rather than partial. Where the output is instead a distinct set - the read-only sweep's distinct event names per principal - stop once three consecutive pages add nothing new to that set, three consecutive pages being the shortest run that separates a converged read from a single page that happened to repeat; a cap on events read would stop on the volume of a principal's traffic instead, and the rare call inside a high-volume principal is the one this agent exists to find. Pages arrive newest first, so that convergence is a floor rather than a proof of completeness - a rare name can still sit on an older page past the run, one the sweep never reached. Report as bounded, naming where it stopped, any result where a token is left unfollowed. And there is no error-code attribute to look up at all: `errorCode` is read from each record's own event JSON, so a denied call is visible on the records these queries already return and an account-wide sweep for denied calls is not available from this API.

Record which regions a lookup reached and where a token was left unfollowed on the same pass that makes the calls, because collecting them by repeating the calls costs the whole pass a second time.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no escalation event appears in the detection window in any region a lookup reached. Report the last 2 days as the detection window these queries read and the last 30 days as the baseline window the second stage reads, with `LookupEvents` as the call that served both, the regions and time windows the event history covers and those it does not, the regions the lookups reached and any they did not with the results bounded by an unfollowed token marked as such, the counts by principal for each of the escalation events named above with the `errorCode` carried on each, and the count of distinct read-only event names per principal, and end.

Only for the principals that appeared:

Build that principal's baseline - which APIs, which regions, which source IPs, which user agents, which hours - and report the departures rather than call counts.

The baseline reads the 30-day window named above rather than the detection window the queries used, and ends on the convergence bound named above, over this principal's APIs, source IPs and user agents.

For each candidate, state the prior call history, whether the source IP and user agent match it, whether each call succeeded or was denied and what changed. The same call set from an account-internal EC2 address on a daily schedule and from an unfamiliar address once are different findings. Report what the principal could do before an escalation call and what it can do after. Where a finding's evidence needs one principal's history in full, read it in full for that one principal in that one region and say that is what you did, which is a named exception rather than a reason to stop converging anywhere else.

Report permission grants that are legitimate but happened outside the account's normal pattern, with who made the grant and by which call. Report each finding as a sequence: principal, source, calls in order, resulting access.

Name the excluded principals explicitly rather than dropping them silently, so that the exclusions are auditable against the next run.

Report an enumeration sequence as intentional where the evidence supports it: a role whose name and permissions match a scanner, cost tool, backup product or infrastructure-as-code runner, the same call set present across the whole of the trail's history at a consistent interval, or a user agent that identifies the tool. Name the evidence. A sweep from a principal with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

CloudTrail: `X-Amz-Target: CloudTrail_20131101.{Operation}` on `cloudtrail.<region>.amazonaws.com`; the same target fully qualified as `com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.{Operation}`.
