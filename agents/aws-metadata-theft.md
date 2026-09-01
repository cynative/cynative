---
description: Determine which EC2 instances expose their instance profile through the metadata service, and what each of those roles reaches.
---

Research which EC2 instances in this account hand their instance profile credentials to a request the instance can be made to issue, and what those roles reach.

Read `HttpTokens`, `HttpEndpoint` and `HttpPutResponseHopLimit` wherever they are set - on running instances, in the account-level default, on every launch template version and on every Auto Scaling launch configuration - and read which instances carry both a public address and an instance profile. Read `EnclaveOptions.Enabled` on each running instance too: a host with an enclave lends that same instance profile to the workload isolated inside it, so the token setting there governs two credential holders rather than one. EC2 and Auto Scaling are regional, so enumerate the enabled regions from the account and read once per region in that result rather than per region in a list of your own. The account-level default is unset in a new account and stays unset until someone sets it, so it describes what the next launch inherits rather than what the running instances do, and it is reported rather than tested in the condition below.

The hop limit is the IP TTL on the metadata service's responses. At 1 the response cannot cross the extra hop into a container on a bridge network; above 1 it can, which puts the instance profile within reach of every container on the host whatever the token setting is.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no running instance has `HttpTokens` set to `optional` or `HttpPutResponseHopLimit` above 1. A public address with an instance profile is ordinary architecture and ranks the findings below rather than producing one. Report the regions the sweep covered and the enabled-region listing it took them from, the `HttpTokens`, `HttpEndpoint` and hop limit values across the launch template versions and Auto Scaling launch configurations as counts, split by whether a running instance or an Auto Scaling group references them, the account-level default with the `HttpTokens` value it carries, stated as unset where no value comes back, and the count of instances carrying both a public address and an instance profile, the running instances whose `EnclaveOptions.Enabled` is true with the `HttpTokens` value each one carries, and which of the instance, launch template and launch configuration enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the instances that are not clean:

Resolve the instance profile's effective permissions and report those rather than the metadata setting. An instance whose role can call `iam:PassRole`, assume other roles, read Secrets Manager or write to S3 is a different finding from one whose role writes to a single log group.

Rank those instances by whether they also carry a public address, which puts an externally reachable process on the same host as the credential source.

Name the enclave hosts inside the count above and rank one above an equivalent instance with no enclave, since a single token setting decides for both the host and the workload sealed inside it.

Report a launch template version or launch configuration setting `HttpTokens` to `optional` in full where an Auto Scaling group or a running instance references it, since the next launch inherits it, and leave the unreferenced versions in the count.

Separate instances with `HttpEndpoint` disabled entirely from instances set to IMDSv2, since the first reaches no metadata at all.

Where the account-level default carries a value and a running instance diverges from it, report the divergence with the instance: the default applies at launch, so an instance that predates it or overrode it keeps its own setting whatever the account now says.

Report a hop limit above 1 as intentional where the evidence supports it: an ECS agent running on the instance with bridge-mode tasks registered to it, or an EKS node whose CNI configuration requires the extra hop. Name the evidence. A hop limit above 1 on an instance with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.
