---
description: Determine which Vertex AI endpoints grant prediction outside the organization and which API keys reach the Generative Language API unrestricted.
---

Research which Vertex AI endpoints in this organization grant prediction to a principal outside it, and which API keys reach the Generative Language API with no restriction. Name the project of every endpoint and key reported, and take the projects you enumerate from the organization's own project listing rather than from the project the credential defaults to.

Read the Vertex AI endpoints and their IAM bindings for `aiplatform.endpoints.predict`, and read API keys with the Generative Language API enabled and no API restriction. A Vertex AI endpoint is regional and each region answers on a host of its own, so read the endpoints for the locations that name a region in the project's own location listing. The Generative Language API is the AI Studio surface rather than the enterprise one, so a key restricted to it and a Vertex AI binding are different exposures and both are read here rather than one standing for the other. A project that has not enabled the API Keys API holds no readable key rather than an unread one: take that service's enablement state from the project's own service listing, which returns each service with its state, and report a project where it is disabled as such rather than reporting the key enumeration as empty or as unresolved. That state answers the key enumeration and not the restrictions carried on a key: where the service is disabled the API restrictions were not read, so name the API key read among the ones that did not answer for that project and do not report those restrictions as present, as clean or as absent. A key reaching the Generative Language API with no restriction is one of the objects this agent asks about, so where the service is disabled it was not read for that project rather than being absent from it, and the answer the report gives it is that it was not read.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no Vertex AI endpoint grants `aiplatform.endpoints.predict` to a principal outside the organization and every API key reaching the Generative Language API carries an API restriction. Report the Vertex AI endpoint inventory with the IAM bindings for `aiplatform.endpoints.predict` on each and the project and location it sits in, each API key's Generative Language API enablement and API restrictions, the service enablement state for the API Keys API per project, and the count of projects and locations the enumeration covered, and which of the endpoint and key enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the endpoints and keys that are not clean:

Resolve the project's enabled service list and report it as the key's scope, since an unrestricted key reaches every one of them rather than the one it was cut for: a standard API key identifies its project rather than a principal, and carries no IAM binding to resolve.

Report each endpoint's predict bindings with the principal type of every member, since `allUsers` and `allAuthenticatedUsers` need no account in this organization while a service account outside it needs one somebody else controls.

Report a reachable endpoint or unrestricted key as intentional where the evidence supports it: a Vertex AI endpoint whose predict binding names a service account in this same organization, or a key whose restrictions name the single API the project's own configuration records it serving. Name the evidence. An endpoint granting predict to a principal outside the organization with no such evidence is not intentional.


Order findings by risk, most consequential first.

Call shapes a run has proven:

Vertex AI: `GET /v1/projects/{project}/locations` on `aiplatform.googleapis.com`; a location's own endpoints at `GET /v1/projects/{project}/locations/{location}/endpoints` on `{location}-aiplatform.googleapis.com`.

Cloud Resource Manager: `GET /v1/projects` on `cloudresourcemanager.googleapis.com`.

Service enablement: `GET /v1/projects/{project}/services/{service}` on `serviceusage.googleapis.com`; the enabled set at `GET /v1/projects/{project}/services?filter=state:ENABLED`.
