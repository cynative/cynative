# API reference lookup

**Tool:** `api_reference`
**Connectors:** `aws` and `github`

`api_reference` returns a short, bounded description of one named API operation, including an `http_request` template the model can fill in. It exists because models often build connector requests from memory and get the path, the protocol or the response format wrong, and then read the resulting local classification failure as a permission denial.

The tool reads public vendor metadata only. It sends no credentials, has no approval prompt, and is not available inside `code_execution`.

## Input

| Field | Connector | Meaning |
|---|---|---|
| `connector` | both | `aws` or `github`. Required. |
| `operation` | both | The exact operation name. Required. |
| `service` | `aws` | The endpoint prefix from the request host, such as `route53` or `iam`. For `api.ecr.us-east-1.amazonaws.com` the prefix is `api.ecr`. |
| `model` | `aws` | Optional. The model directory, used to choose between models that share an endpoint prefix (for example `ses` and `sesv2`). |

For AWS the operation is the Smithy name (`ListHostedZones`). For GitHub it is the OpenAPI `operationId` (`repos/get`). A name is matched exactly first, then case-insensitively.

## What comes back

The result is JSON, capped at 8192 bytes. A `found` or `incomplete` result contains:

- `reference`: the protocol, HTTP method and path template, API version, a summary (at most 600 characters), the endpoint, the inputs (name, wire name, location, required, type, description of at most 200 characters), the body encoding, how the response is encoded and parsed, pagination, the metadata source with its version and SHA-256, and any `gaps` and `limitations`.
- `request_template`: an `http_request` argument object with `<Placeholder>` values. Only required inputs appear in it. Path inputs replace the label in the path, required query inputs join the URL, header inputs go to `headers`, and body inputs go to a form or JSON body with the matching `Content-Type`. For AWS the template carries the `aws_auth` block with the signing service name. Credentials and resource identifiers never appear.
- `note`: a reminder to replace every placeholder. A required input the tool could not render appears as `<Name:unrendered>`, so an incomplete template never looks executable as it stands.

At most 25 optional inputs are listed, and `inputs_truncated` is set when more were dropped. If the output is over the cap, the tool drops optional inputs first, then input descriptions, then the summary. If it is still over, it returns a minimal `incomplete` result with the limitation `reference exceeds the output budget` and no template.

## Outcomes

The outcome is one of the following. When more than one applies, the first in this list wins.

1. `unsupported`: the connector is not configured in this session, or it has no reference support (every connector other than `aws` and `github`).
2. `unavailable`: the metadata could not be loaded or parsed. For AWS the reason is the load error text truncated to 500 characters. For GitHub it is a fixed message. This is never reported as `not_found`.
3. `not_found`: no model for the AWS endpoint prefix, a `model` that does not belong to the prefix (the choices list the valid ones), no operation by that name, or invalid arguments or an empty `operation`.
4. `ambiguous`: several models for the prefix define the operation and no `model` was given, or the case-insensitive match hits several names. At most 5 choices are returned.
5. `unsupported`: the operation was found in a model whose protocol the tool cannot describe (`ec2Query`).
6. `incomplete`: the operation has a blocking gap, listed in `gaps`.
7. `found`.

A `found` or `incomplete` result counts as progress for the run's stuck-detection. Every other outcome counts as a failure, so a model that loops on bad lookups stops at `max_consecutive_failures` like any other failing tool.

## AWS

Supported protocols are restXml, restJson1, awsQuery, and awsJson1.0 and 1.1. Other protocols, including `ec2Query`, answer `unsupported`.

Templates follow the service's own protocol:

- restXml and restJson1: the `@http` method and URI, with labels in the path, `@httpQuery` members in the URL and `@httpHeader` members in headers, each under its wire name. restJson1 required body members go into a JSON body.
- awsQuery: `POST /` with `Content-Type: application/x-www-form-urlencoded; charset=utf-8` and a form body of `Action`, `Version` and the required members.
- awsJson1.0 and 1.1: `POST /` with an `X-Amz-Target` header and `Content-Type: application/x-amz-json-1.0` or `1.1`, and a JSON body of the required members.

Required members the renderer cannot place (see the types below) appear in the template as `<Name:unrendered>`.

Required inputs of these types are rendered: string, enum, intEnum, integer, long, short, byte, boolean, float and double. A required input of any other type (timestamp, blob, list, map, structure, union, document) cannot be rendered and makes the result `incomplete`.

A result is also `incomplete` when:

- the operation has a required restXml request body member (XML request bodies are not generated);
- a required input is bound in a way the renderer does not handle, such as an `@httpPayload` member; or
- the response is a raw payload. An output `@httpPayload` that targets a blob, string or document, or a streaming member, is raw. An output `@httpPayload` that targets a structure or union is an ordinary XML or JSON document and is not a gap.

Response guidance is generated from the model. For XML responses (restXml and awsQuery) it says to parse with `xml.parse(response.body)` inside `code_execution`, notes that every leaf is a string (compare `IsTruncated === 'true'`, never its truthiness), gives the element path of each top-level list (for example `Roles.member` for IAM `ListRoles`, `HostedZones.HostedZone` for Route53 `ListHostedZones`), and gives `x == null ? [] : [].concat(x)` to normalize a list that parses as one object or is absent. An operation whose output has no body members (none at all, or only header and status bindings) is described as returning no modeled body fields, to be read from the status and headers. For awsQuery the response is still an XML envelope (`<Op>Response` with `ResponseMetadata`) with no result fields.

Pagination follows the model: an operation is paginated only if it carries `@paginated`, and a service-level `@paginated` fills only the members the operation leaves unset. Otherwise the style is `unspecified`.

**Endpoint.** If the model's endpoint rules contain the exact literal `https://<prefix>.amazonaws.com` (for example `https://route53.amazonaws.com` or `https://iam.amazonaws.com`), that URL is used. Otherwise the endpoint is the regional form `https://<prefix>.<region>.amazonaws.com`, and only that fallback carries the limitation that other partitions, FIPS and dual-stack endpoints are not covered, so the template is wrong for a China or GovCloud region or a FIPS endpoint. The `aws_auth.service` value is the SigV4 signing name from the model. `region` is left out of the template, as it is for any other AWS request, and the model supplies it.

**Source.** The models come from the `aws/api-models-aws` archive that the AWS gate already downloads and caches under `<cache.dir>/aws`. A lookup never runs the IAM policy fetch and makes no credentialed call.

## GitHub

The operation is the OpenAPI `operationId`. The template uses `https://api.github.com` plus the path with `<param>` placeholders, required query parameters, and `Accept: application/vnd.github+json`.

- The connector strips `X-GitHub-Api-Version`, so the server's default API version applies. The reference reports the document's `info.version` and says so as a limitation.
- A required request body is rendered when it is `application/json` and its schema, after at most one local `$ref`, is an object. Its required properties become body inputs. A required property that is not a supported scalar gets the gap `required input <name> (<type> in body) cannot be rendered` (`issues/create` is an example) and the result is `incomplete`. A required body that is not JSON, is a `$ref`, or is not an object gets the gap `request body is not a JSON object the template can render`.
- An optional request body (`required` false or absent) never adds inputs or gaps. If it cannot be rendered, or has required properties, the template omits it and the reference carries only the limitation `optional request body is not rendered`.
- Pagination is reported as `link-header`, with `page` and `per_page`, only when the operation has both parameters and its 200 response declares a `Link` header. This is a heuristic and the result labels it as one: follow `rel="next"` in the response `Link` header. Otherwise the style is `unspecified`.
- Response guidance reports the declared media type: JSON, no body, or other text (for example `markdown/render` returns `text/html`).

**Source.** GitHub's public REST OpenAPI description (`github/rest-api-description`), the same document the GitHub gate downloads. It feeds two caches under `<cache.dir>/github`: `table.json` for the gate and `docs.json` for `api_reference`. When the gate's table fetch downloads the document, it hands those bytes to the docs cache once, so that cold start costs one download. If an `api_reference` lookup comes first on cold caches, the docs cache fetches the document itself and the gate's table fetches it again later. The table is never served from the docs cache. A failure to fetch, parse or admit the docs makes lookups answer `unavailable` and does not touch the gate's table.

Because the two caches can be filled from different downloads, the docs can describe an operation that an older cached table does not know yet. The reference states the document version it was read from.

## Offline use

Both sources are cached on disk. With a warm cache, lookups work without network access. A cold AWS archive or a cold GitHub docs cache needs one fetch, and a lookup answers `unavailable` if that fetch fails. After a Cynative upgrade the docs cache is filled on first use even though the gate's table may already be warm.

## Unmatched-request message

When the AWS or GitHub action gate finds that a request matches no operation in its metadata, `http_request` returns an explanatory error in place of the bare gate text. For example, a Route53 request to `/2013-04-01/hostedzones` produces:

```
GET "/2013-04-01/hostedzones" on aws/route53 matched no operation in the cached API metadata. The gate stopped before attaching credentials or sending anything; this says nothing about the principal's permissions. Check the request shape against the operation reference. Candidates: ListHostedZones (GET /2013-04-01/hostedzone). For an operation's request template call api_reference with {"connector":"aws","operation":"ListHostedZones","service":"route53"}. (gate detail: "aws_hardening: could not resolve IAM action for operation: no candidate serves the request for \"route53\"")
```

The message echoes only the method and a truncated, escaped path (200 characters), and the gate detail is truncated to 300 characters. It names at most 3 candidates, found by three cheap rules: the request used another protocol's shape for an operation the service defines (AWS), the path matches under another method (AWS REST, GitHub), or the path is a near miss with one segment within edit distance 2 (AWS REST, GitHub). With more than 3 candidates it shows none. When exactly one operation is suggested, its name fills the `api_reference` call.

The message is text only. It never changes what the gate allows or denies, never rewrites or retries the request, and the original gate error stays reachable through `errors.Is`. It appears only when the request matched nothing. Policy denials, unmapped IAM actions, metadata failures, and requests where no model matched but some candidate model for the prefix uses an unsupported protocol keep their original text. The vendor descriptions are never included.

Because the hint reads the GitHub docs cache, the first unmatched GitHub request on a cold docs cache costs one fetch on the error path, unless the gate's table was downloaded in this process, in which case its bytes were already handed to the docs cache. The metadata can also be stale: a request the cache does not know may still be valid on the server.

## Limits

- Lookup is by exact name. There is no search or listing of operations.
- Other connectors answer `unsupported`.
- Schemas are not expanded beyond the rules above, and XML request bodies are not generated.
- The reference is only as current as the cached vendor metadata.
