# Test data

- `openapi-docs.json`: four operations (`repos/get`, `issues/list-for-repo`, `issues/create`, `markdown/render`)
  excerpted from
  https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json
  on 2026-10-01. Response `content` schemas were dropped while their media types were kept; each operation keeps its
  `x-github` block and the parameter, request-body schema and `Link` header components it references.
