# Test data

- `openapi-docs.json`: four operations (`repos/get`, `issues/list-for-repo`, `issues/create`, `markdown/render`)
  excerpted from
  https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json
  on 2026-10-01. Response `content` schemas were dropped while their media types were kept; each operation keeps its
  `x-github` block and the parameter, request-body schema and `Link` header components it references.
- `golden/`: byte-for-byte output of the docs code for `openapi-docs.json` and the synthetic descriptions in
  `openapidoc_golden_test.go`: the serialized docs, the references (with the fields their JSON form hides) and the
  hints, plus `unmatched.txt`, the whole unmatched-request diagnostic that
  `internal/auth/unmatched_golden_internal_test.go` records. A missing file is recorded on the next test run, which
  then fails; review the recording before committing it. A change to any of these bytes changes what api_reference
  returns, what the docs cache holds or what a denied request says.
