# AWS hardening test fixtures

Trimmed, hand-inspectable fixtures for the `internal/auth/aws` tests. Each
covers only what the test files reference, to stay small.

- `smithy_models/` — trimmed Smithy 2.0 JSON-AST service models, parsed by the
  classifier and `ModelArchive`/`ParseModel` tests.
- `serviceref/` — trimmed AWS Service Reference per-service documents, parsed by
  the `ServiceRefRegistry` / `ActionResolver` tests.
- `iam_dataset/` — a trimmed `iann0036/iam-dataset` `map.json`, parsed by the
  `IAMDatasetRegistry` tests.
