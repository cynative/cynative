---
description: Determine who can invoke Bedrock model endpoints in an AWS account, what a hijacked one reaches and whether abuse would appear in the call record.
---

Research who can invoke the model endpoints in this account, what a hijacked one would reach or spend, and whether abuse would appear in the call record.

Read Bedrock API keys - the service-specific credentials IAM users hold for `bedrock.amazonaws.com`, which `iam:ListServiceSpecificCredentials` returns one user at a time - for expiry past the current date. Read the IAM principals with AmazonBedrockFullAccess or AdministratorAccess attached by listing the entities each policy is attached to, which is a single call against its ARN rather than an expansion of every principal's permissions, and list the users in any group that call returns, since a group holds the policy without the user appearing among the returned entities. Classify a key as unrestricted or administrative where the IAM user holding it is among those entities or among a listed group's users. Read whether each Bedrock agent names a guardrail in its configuration, and the `agentResourceRoleArn` each Bedrock agent runs as. The listing carries the guardrail's identifier and nothing about what that guardrail filters, so report a guardrail as named or absent rather than as effective; the execution role is on the per-agent read rather than the listing, and it is what an injected instruction inherits. Compare those role ARNs across the agents the account holds: a role two agents share gives each one the union of what both were meant to reach, and leaves the call record unable to say which of them acted. A deployed agent version keeps the role it was cut with and that role does not come back here, so the comparison covers the draft role each agent runs as and is reported as covering that.

Take a summary of `InvokeModel` and its equivalents grouped by principal and region, from the trail's management events, which is what a trail lookup returns. The window is the last 30 days and the baseline is the 60 days before it, which together stay inside the 90 days a trail lookup returns, so state both dates with the report and use the same pair on every run.

Three things bound that summary, and each of them returns an empty result that reads as a quiet account. The lookup answers for one region at a time, and a multi-region trail does not change that: an event recorded in a region is retrievable only by calling against that region, so enumerate the enabled regions from the connected account and call once per region in that result rather than per region in a list of your own, and name any region you could not reach. A response carries at most 50 events with a token for the next page, so follow that token to exhaustion and report the summary as bounded, naming where it stopped, wherever you do not. `InvokeModelWithBidirectionalStream`, `GetAsyncInvoke` and `StartAsyncInvoke` are recorded as data events instead, so a lookup cannot see them and their absence is unresolved rather than an absence of invocation.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no Bedrock API key is unrestricted or administrative and every Bedrock agent names a guardrail. Report the key inventory with each Bedrock API key's unrestricted-or-administrative classification, its expiry as `iam:ListServiceSpecificCredentials` returns it for `bedrock.amazonaws.com`, and the principals with AmazonBedrockFullAccess or AdministratorAccess attached; each Bedrock agent's guardrail and its `agentResourceRoleArn`, with any `agentResourceRoleArn` more than one agent holds named as shared and the draft-role bound stated; and the `InvokeModel` management-event summary by principal and region for the last 30 days as the window and the 60 days before it as the baseline, both named with their dates, naming the enabled regions it covers and any region not reached, marked bounded wherever a next-page token was left unfollowed, and with `InvokeModelWithBidirectionalStream`, `GetAsyncInvoke` and `StartAsyncInvoke` marked unresolved, and which of the key and agent enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the keys and agents that are not clean:

Report the principal each unrestricted key maps to and its other permissions.

Compare the window against the baseline period and report calls from a principal with no invocation in the baseline, calls in a region where the baseline period recorded none for that principal, and sequences where model-listing calls or `AccessDenied` results precede sustained invocation, stating the principal, the model, the region and the time range. That comparison is the expensive work this agent defers, since it means building two summaries and differencing them.

For each agent naming no guardrail, report its configured data sources and action groups as the points where text enters its context, and report the knowledge bases behind those data sources as what an injected instruction can reach.

Resolve the permissions of each agent's execution role and report them with the agent, since that is what a hijacked one acts with rather than what it was asked to do. An agent whose role reaches secrets, storage the account writes elsewhere, or another role it can assume is a different finding from one that reaches a single knowledge base. Where that role is one the report above named as shared, resolve it once and report the result against every agent holding it.

Report a Bedrock agent naming no guardrail as intentional where the evidence supports it: an agent whose data sources all sit inside this account and whose execution role reaches a single knowledge base and nothing else. Name the evidence. An agent naming no guardrail, whose execution role reaches secrets, storage the account writes elsewhere or another role it can assume, with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Bedrock Agents: `bedrock:ListAgents` answers at `POST /agents/` on `bedrock-agent.<region>.amazonaws.com`, signing as `bedrock`.

CloudTrail: `X-Amz-Target: CloudTrail_20131101.{Operation}` on `cloudtrail.<region>.amazonaws.com`; the same target fully qualified as `com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.{Operation}`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.
