# Azure spec fixtures

Trimmed copies of files from `Azure/azure-rest-api-specs` (MIT) at commit
`67d29f055c6c0ca0ff8262181837b1e9fc049c4a`, under their repository paths, and `catalog.json`, a subset of the
providerOperations catalog the azure gate caches (`Microsoft.Compute`, `Microsoft.Resources`, `Microsoft.Storage`,
`Microsoft.Authorization`).

Each spec file keeps only the operations `compat_internal_test.go` names, their `parameters`, and every parameter and
definition those reach through `$ref`, across files. Response schemas and `x-ms-examples` are dropped.

To refresh with a newer commit:

1. Download each file under `specification/` here from
   `https://raw.githubusercontent.com/Azure/azure-rest-api-specs/<commit>/<path>`. If an operation file now refs
   another `common-types` version, download that file too.
2. Trim each operation file. Keep the top-level `swagger`, `info`, `host`, `schemes`, `consumes` and `produces`, and
   under `paths` and `x-ms-paths` only the operations the test names. In each kept operation drop `x-ms-examples` and
   cut every response to its status code and description. Then keep each `parameters` and `definitions` entry, in any
   file, that the kept operations or their path items' parameters reach through `$ref`, following the refs inside
   what is kept, and drop every other entry. Write the JSON with two-space indentation and sorted keys.
3. Rebuild `catalog.json` from a catalog the azure gate cached, `~/.cynative/cache/azure/catalog/azure-AzureCloud.json`:
   keep `clouds` and only the four providers above, and write it with one-space indentation and sorted keys.
4. Check that no fixture holds an account identifier:
   `grep -rEn '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' internal/auth/azure/testdata/specs`.
   Every hit must be a well-known Azure constant, such as a built-in role id; remove any subscription, tenant or
   principal id.
5. Update the commit above, `compatCommit` and the table in `compat_internal_test.go`, and run
   `go test ./internal/auth/azure -run TestGateCompatibility`.
