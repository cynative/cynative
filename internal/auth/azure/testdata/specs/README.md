# Azure spec fixtures

Trimmed copies of files from `Azure/azure-rest-api-specs` (MIT) at commit
`67d29f055c6c0ca0ff8262181837b1e9fc049c4a`, under their repository paths, and `catalog.json`, a subset of the
providerOperations catalog the azure gate caches (`Microsoft.Compute`, `Microsoft.Resources`, `Microsoft.Storage`,
`Microsoft.Authorization`).

Each spec file keeps only the operations `compat_internal_test.go` names, their `parameters`, and every parameter and
definition those reach through `$ref`, across files. Response schemas and `x-ms-examples` are dropped.

To refresh: run the fetch and trim steps of Task 12 in the implementation plan with a newer commit, regenerate
`catalog.json` from a fresh `~/.cynative/cache/azure/catalog/azure-AzureCloud.json`, update the commit above and the
table in the test, and run `go test ./internal/auth/azure -run TestGateCompatibility`.
