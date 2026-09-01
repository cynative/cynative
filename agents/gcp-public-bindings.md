---
description: Find GCP resources granting allUsers or allAuthenticatedUsers, and establish what each public binding permits.
---

Research which Cloud Storage buckets, BigQuery datasets, Cloud Functions, Cloud KMS keys and Secret Manager secrets in this organization grant access to `allUsers` or `allAuthenticatedUsers`, and which data relies on project IAM alone. Name the project of every resource reported, and take the projects you enumerate from the organization's own project listing rather than from the project the credential defaults to, walking the folder tree beneath the organization rather than only the projects parented directly on it, resolving which organization that is from the `parent` each project carries rather than from an organization listing, which the ceiling does not reach.

One search carries the bindings on all five: `cloudasset.assets.searchAllIamPolicies` scoped to the organization returns the IAM policy on each Cloud Storage bucket, BigQuery dataset, Cloud Function, Cloud KMS key and Secret Manager secret alongside the policies bound at the folder and the organization above them, and reports the resource each binding is bound to so you can place it at the right level. Read the project's IAM policy with it, since an inherited binding does not appear on the resource's own policy. That search takes a query filter and applies it server-side, so ask it for the two principals rather than reading every policy in the organization back. Enumerate buckets with `storage.buckets.list` rather than reading each one: it returns the same bucket fields a single read would. Take the dataset inventory the counts below need from Cloud Asset's own resource search rather than from a per-project dataset listing. Take a disk's customer-supplied key state from the instance listing's own attached disk records, which carry that key where one is set, rather than from the asset inventory, whose attributes for a disk are its size, type and users. Separate the two principals as you read them: `allUsers` is anyone on the internet, with or without a Google account, and `allAuthenticatedUsers` is anyone authenticated as a Google account or service account anywhere, which is a smaller set but still one this organization does not control.

A project that has not enabled the Cloud Resource Manager API holds no readable policy, and one that has not enabled the Compute Engine API holds no instance or disk, rather than unread ones: take that service's enablement state from the project's own service listing, which returns each service with its state, and report a project where either is disabled as such rather than reporting the reads it serves as empty or as unresolved.

Read the organization policy `constraints/iam.allowedPolicyMemberDomains` alongside them, from Cloud Asset's org-policy analysis for that named constraint, which returns the consolidated rules in force and the resource each result is attached to. It is the control that prevents these bindings existing, so its state decides whether a binding is a gap in enforcement or an exception granted above it.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no binding names either principal. Report the IAM policies named above as counts by the level each binding sits at, the resource counts split by principal into `allUsers` and `allAuthenticatedUsers`, the `constraints/iam.allowedPolicyMemberDomains` state with the projects and folders it applies at, the count of BigQuery datasets with no customer-managed key and Compute Engine disks with no customer-supplied key, the service enablement state for the Cloud Resource Manager API per project, and the count of projects the enumeration covered, and which of the policy and resource enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the resources that are not clean:

Rank the public bindings by the role's permissions: `roles/secretmanager.secretAccessor` and `roles/cloudkms.cryptoKeyDecrypter` first, then Storage and BigQuery write roles, then read roles. Within each rank report `allUsers` ahead of `allAuthenticatedUsers`, since the first needs no account and the second at least records one.

For public Cloud Functions the invoker binding is how an HTTP function is served, so resolve the function's runtime service account and report its project bindings as the finding.

For the datasets and buckets you reported above, read whether each has a customer-managed key and compare the principals holding data-read access against the principals holding `roles/cloudkms.cryptoKeyDecrypter` or another role granting `cloudkms.cryptoKeyVersions.useToDecrypt` on the key that would protect it. Report the resources where those sets differ, since that difference is what a key adds, and where they are the same name the resource within the count.

State for each binding whether `constraints/iam.allowedPolicyMemberDomains` is enforced at its project: an unenforced constraint makes the binding a gap, and an enforced one with an exception makes it a granted exception, and those are different findings.

Report a public resource as intentional where the evidence supports it: a bucket with a website configuration or a Cloud CDN backend in the project naming it, a BigQuery dataset carrying a public-dataset label, or a Cloud Function that is the documented backend of a public endpoint in the project. Name the evidence. A binding naming either principal with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Cloud Resource Manager: `GET /v3/projects:search`, and `GET /v3/projects?parent=organizations/{id}`, on `cloudresourcemanager.googleapis.com`.

Project IAM policy: `POST /v1/projects/{project}:getIamPolicy` on `cloudresourcemanager.googleapis.com`.

Compute Engine: `GET /compute/v1/projects/{project}/aggregated/instances` on `compute.googleapis.com`.

Service enablement: `GET /v1/projects/{project}/services/{service}` on `serviceusage.googleapis.com`.

Cloud Asset: `GET /v1/organizations/{id}:searchAllIamPolicies?query={filter}` on `cloudasset.googleapis.com`; the resource inventory at `GET /v1/organizations/{id}:searchAllResources?assetTypes={type}`, and a named constraint at `GET /v1/organizations/{id}:analyzeOrgPolicies?constraint={constraint}`; each carries an `x-goog-user-project` header naming the project the credential defaults to.
