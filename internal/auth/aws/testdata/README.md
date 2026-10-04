# AWS hardening test fixtures

Trimmed, hand-inspectable fixtures for the `internal/auth/aws` tests. Each
covers only what the test files reference, to stay small.

- `smithy_models/` — trimmed Smithy 2.0 JSON-AST service models, parsed by the
  classifier and `ModelArchive`/`ParseModel` tests.
- `serviceref/` — trimmed AWS Service Reference per-service documents, parsed by
  the `ServiceRefRegistry` / `ActionResolver` tests.
- `iam_dataset/` — a trimmed `iann0036/iam-dataset` `map.json`, parsed by the
  `IAMDatasetRegistry` tests.
- `smithy_docs/` - Smithy models trimmed from `aws/api-models-aws` main on 2026-10-01, parsed by the
  documentation extractor tests. Kept the service shape's `aws.api#service`, `aws.auth#sigv4`,
  protocol, `smithy.api#paginated` and title traits; replaced the endpoint ruleset with a flat list
  of its literal URL templates (the extractor only scans URLs); kept the listed operations and every
  shape they reference transitively.
