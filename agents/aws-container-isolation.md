---
description: Determine which running ECS tasks cross the boundary to the host that runs them, what the container instance behind each one reaches, and which EKS clusters carry no cluster security group.
---

Research which ECS task definitions actually running in this account cross the boundary to the host that runs them, and which EKS clusters carry no cluster security group.

Take the revisions to read from the running services and tasks themselves, each of which records the revision it runs, and set that result against the account's task definition listing to get the revisions nothing references. Read those referenced revisions and take `pidMode`, `ipcMode` and `networkMode` from the revision itself and `privileged`, `readonlyRootFilesystem` and `user` from each entry in `containerDefinitions`, together with the launch type of the service or task that references it. ECS and EKS are regional, so enumerate the enabled regions from the account and list clusters, services, tasks and task definitions once per region in that result rather than per region in a list of your own.

Read `clusterSecurityGroupId` under `resourcesVpcConfig` on each EKS cluster, which the cluster describe returns. It names the security group the control plane attaches to every managed node and to the cluster's own elastic network interfaces, so it is the one network boundary the EKS API states for pod-to-pod and node-to-control-plane traffic; a cluster returning no value for it has none. What the cluster's NetworkPolicy objects say is not visible through the EKS API and is outside this agent's scope.

A task running on Fargate can carry none of `privileged: true`, `pidMode: host`, `ipcMode: host` or `networkMode: host`, so a revision carrying one of them has a host to cross to whatever launch type its running service or task records, and a revision carrying none of them is not a finding here.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no in-use revision sets `privileged: true`, `pidMode: host`, `ipcMode: host` or `networkMode: host` and every EKS cluster returns a `clusterSecurityGroupId`. Report the `readonlyRootFilesystem` and `user` counts drawn from `containerDefinitions` per task definition family with that family's launch types, the revisions no service or task references as a count, each EKS cluster's `resourcesVpcConfig` with the `clusterSecurityGroupId` it carries, and the regions the sweep covered and the enabled-region listing it took them from, and which of the task definition and cluster enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the revisions and clusters that are not clean:

Resolve the container instance's IAM role for each affected task and report its permissions, since that is what a container crossing to the host reaches on top of its own task role.

For a cluster with no cluster security group, report its node groups and Fargate profiles as the extent the EKS API establishes, and the cluster's endpoint access state alongside, since nothing then bounds traffic between the workloads those node groups run.

Name only the containers that appear in a boundary finding above within the `readonlyRootFilesystem` and `user` counts.

For a revision that no service or task references but that sets `privileged: true`, `pidMode: host`, `ipcMode: host` or `networkMode: host`, resolve the principals holding `ecs:RunTask` on the cluster and `iam:PassRole` on the revision's `taskRoleArn` and `executionRoleArn` where either is set, and report the principals holding both, since the revision is one call away from running.

Report a host-mode or privileged revision as intentional where the evidence supports it: an image that is a monitoring or logging agent the account runs on every container instance, or a task role whose permissions reach only telemetry endpoints. Name the evidence. A revision with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

ECS: `X-Amz-Target: AmazonEC2ContainerServiceV20141113.{Operation}` on `ecs.<region>.amazonaws.com`.

EKS: `GET /clusters` on `eks.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.
