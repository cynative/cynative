---
description: Find credentials sitting in AWS resource configuration and bound what each one reaches using the account's own APIs.
---

Research whether any credential is sitting in plaintext in the configuration of this account's resources, and what each one reaches.

Fetch the eleven configuration surfaces that carry free-text values: EC2 instance user data, launch template user data, Lambda function environment variables, ECS task definition environment variables, AWS Batch job definition container environment variables and command, CodeBuild project environment variables and source repository URL, CloudFormation stack outputs, SSM document parameter default values, Step Functions state machine definitions, Data Pipeline definitions and SageMaker notebook lifecycle configuration scripts. Take the SSM defaults from the document description, which carries each parameter's default value without the document body. Data Pipeline does not answer in every enabled region, so a region where it has no endpoint holds no pipeline rather than an unread one: name those regions among the ones the enumeration covered rather than reporting the fields as unresolved there. A SageMaker enumeration that did not reach the service leaves an unread scope rather than an account holding no lifecycle configuration. Read the rotation configuration and creation date on every Secrets Manager secret in the same pass. Every surface named here is regional, so enumerate the enabled regions from the account and read once per region in that result rather than per region in a list of your own.

Filter what comes back. Discard ARNs, account IDs, resource names, public endpoints, template markers such as `${...}` and placeholder values. Keep private key blocks, connection strings containing a password, URLs with an embedded token and access key IDs.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no value passes the filter. Report the regions the sweep covered and the enabled-region listing it took them from, which of the eleven configuration surfaces named above you read and which you could not, naming each one you could not, the count discarded by reason, and the Secrets Manager secrets with rotation disabled with their creation dates as a count, and end.

Only for the values that are not clean:

Establish reach using the account's own APIs and nothing else. An `AKIA` identifier resolves to an IAM user whose permissions you can read; where it resolves to the account root user instead or matches no IAM user, the finding is that its reach cannot be bounded that way. A database host in a connection string either matches an RDS, Redshift, DocumentDB, Neptune or ElastiCache endpoint in the account or it does not, and where it matches nothing the finding is that the credential's reach cannot be bounded from here. DocumentDB's and Neptune's cluster endpoints come back from the same RDS enumeration, told apart by `Engine`, rather than from an enumeration of their own.

Report which permission already exposes each value: Lambda environment variables to `lambda:GetFunctionConfiguration`, CloudFormation outputs to `cloudformation:DescribeStacks`, ECS task definitions to `ecs:DescribeTaskDefinition`, Batch job definitions to `batch:DescribeJobDefinitions`, and Step Functions definitions to `states:DescribeStateMachine`.

Name the Secrets Manager secrets from the count above whose name matches the key or resource carrying a value you retained, and report the creation date of any with rotation disabled next to the copy found elsewhere: automatic rotation is disabled, and the secret was created on that date, not that the value itself has never changed and not that rotation has been off since creation.

Report a retained value as intentional where the evidence supports it: an `AKIA` identifier whose IAM user's permissions reach only what a bucket policy in this account already grants to everyone, or a value the account's own deployment substitutes at runtime, evidenced by an SSM parameter or a Secrets Manager secret of the same name. Name the evidence. A retained value with no such evidence is not intentional.

Order findings by risk, most consequential first.

Call shapes a run has proven:

Step Functions: `X-Amz-Target: AWSStepFunctions.{Operation}` with a `Content-Type` of `application/x-amz-json-1.0` on `states.<region>.amazonaws.com`.

CloudFormation: `GET /?Action={Operation}&Version=2010-05-15` on `cloudformation.<region>.amazonaws.com`.

ECS: `X-Amz-Target: AmazonEC2ContainerServiceV20141113.{Operation}` on `ecs.<region>.amazonaws.com`.

Lambda: `GET /2015-03-31/functions` on `lambda.<region>.amazonaws.com`.

SageMaker: `X-Amz-Target: SageMaker.ListNotebookInstanceLifecycleConfigs`, with a `Content-Type` of `application/x-amz-json-1.1`, on `api.sagemaker.<region>.amazonaws.com`.

Neptune and DocumentDB: the RDS API on `rds.<region>.amazonaws.com`.

Redshift: `GET /?Action=DescribeClusters&Version=2012-12-01` on `redshift.<region>.amazonaws.com`.

EC2: `GET /?Action=DescribeRegions&Version=2016-11-15` on `ec2.<region>.amazonaws.com`. STS: `GET /?Action=GetCallerIdentity&Version=2011-06-15` on `sts.amazonaws.com`.

IAM: `GET /?Action={Operation}&Version=2010-05-08` on `iam.amazonaws.com`.
