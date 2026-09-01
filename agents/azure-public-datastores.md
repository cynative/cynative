---
description: Determine which Azure SQL, MySQL, PostgreSQL, Cosmos DB and Databricks deployments admit outside connections and what authenticates them.
---

Research which SQL Servers, MySQL and PostgreSQL flexible servers, Cosmos DB accounts and Databricks workspaces in this subscription admit connections from outside the virtual network, and what authenticates those connections.

Read the firewall rules on each SQL Server, the allow-public-access-from-any-Azure-service setting on each PostgreSQL flexible server, `disableLocalAuth` and `publicNetworkAccess` on each Cosmos DB account, and public network access and VNet injection on each Databricks workspace. A SQL firewall rule of 0.0.0.0 to 255.255.255.255 admits the internet; a rule of 0.0.0.0 to 0.0.0.0 is the allow-Azure-services entry, which admits every Azure subscription in every tenant rather than only this one. A subscription that has never used one of these five services has not registered its resource provider, and a provider in that state holds none of its resource type rather than an unread one: take the registration state from the subscription's own provider listing, which returns every provider with its `registrationState`, rather than from a path naming one provider, and report it rather than reporting the enumeration as empty or as unresolved.

Read the transport settings on the same flexible servers by their own parameter names: `require_secure_transport` on MySQL and PostgreSQL flexible servers, and `tls_version` on MySQL. The retired single-server `sslEnforcement` property is a different field on a different deployment model and does not appear on the servers this agent scopes to.

Read the SQL Server transparent data encryption state as two facts rather than one: whether TDE is on, and whether its protector is a customer-managed key in a Key Vault or the service-managed key. Read the auditing state and the Defender for SQL state alongside them, and the Databricks workspace customer-managed key configuration.

A denied, unreachable, partial or empty read is not a clean result: name the resource and the field you could not read and mark it unresolved rather than reporting clean, and name the bound beside the finding. Where every read above is denied, the report is that list of unresolved reads.

Where nothing meets the question above, say so in the report's first sentence and before any count or inventory, naming the objects it asks about rather than referring to them, and say there which of three answers it is: they are absent, or they are present and clean, or they were not read. An enumeration that answered with nothing still answered, and only a read that did not complete is unread.

Stop here if no SQL Server carries a rule of 0.0.0.0 to 255.255.255.255 or 0.0.0.0 to 0.0.0.0, no PostgreSQL flexible server allows public access from any Azure service, every Cosmos DB account has `publicNetworkAccess` disabled, every Databricks workspace is VNet-injected with public access disabled, every MySQL and PostgreSQL flexible server has `require_secure_transport` on and every MySQL flexible server is at `tls_version` 1.2 or above. Local authentication is how nearly every Cosmos DB client connects, so an account permitting it is the common case rather than the exceptional one and gating on it would run the expensive stage almost everywhere; gating on `publicNetworkAccess` instead is what keeps a publicly reachable account out of the clean branch. Report the per-service inventory with each SQL Server's firewall rules, each Cosmos DB account's `disableLocalAuth` and `publicNetworkAccess`, and each Databricks workspace's public network access and VNet injection state; the transparent data encryption state with each server's TDE protector split into customer-managed and service-managed; the auditing and Defender for SQL states as counts; the Databricks customer-managed key state; and the registration state of the resource providers named above, and which of the five service enumerations above answered and which did not, naming each one that did not rather than counting it as zero, and end.

Only for the resources that are not clean:

List the databases on each affected server, and report Cosmos DB accounts permitting the account key alongside their public network access and private endpoint connections. The account key grants full data-plane access, does not expire and attributes to no principal.

For Databricks workspaces without VNet injection, report the public network access setting and the role assignments on the workspace's managed resource group, since the workspace's network path is not governed by the subscription's network controls.

Report each server with `require_secure_transport` off, and each MySQL server below `tls_version` 1.2, with that server's firewall rules, which describe what shares the path the credentials cross.

Name the affected servers within the TDE, auditing and Defender for SQL counts, and report a server whose TDE protector is service-managed separately from one with no TDE at all: the first encrypts against media loss only, since the service holds the key.

Report a firewall rule as intentional where the evidence supports it: a single address, or a bounded block that another resource in the subscription also names such as a NAT gateway public IP or an application gateway frontend. Name the evidence. A rule spanning the whole address space with no such evidence is not intentional.


Order findings by risk, most consequential first.


Call shapes a run has proven:

Resource providers: `GET /subscriptions/{subscriptionId}/providers` on `management.azure.com`.
