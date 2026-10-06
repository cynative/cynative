package gitlab_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

// docsFixture is an excerpt shaped like GitLab's openapi_v3.yaml: quoted and unquoted response codes, a 200 with
// no content, oneOf string/integer ids, a $ref JSON body, a multipart body, every Grape path form, NuGet literal
// parentheses, a dotted last segment, an undeclared label, an untagged operation and credential-named inputs.
const docsFixture = `openapi: 3.0.0
info:
  title: GitLab REST API
  version: '19.5'
servers:
- url: https://{hostname}
paths:
  /api/v4/projects/{id}:
    get:
      tags: [Projects]
      operationId: getApiV4ProjectsId
      summary: Get a single project
      parameters:
      - {in: path, name: id, required: true, schema: {oneOf: [{type: string}, {type: integer}]}}
      responses:
        '200': {description: ok, content: {application/json: {}}}
  /api/v4/projects/{id}/merge_requests:
    get:
      tags: [Merge requests]
      operationId: getApiV4ProjectsIdMergeRequests
      parameters:
      - {in: path, name: id, required: true, schema: {oneOf: [{type: string}, {type: integer}]}}
      - {in: query, name: page, schema: {type: integer}}
      - {in: query, name: per_page, schema: {type: integer}}
      - {in: query, name: sudo, schema: {type: string}}
      - {in: header, name: Private-Token, schema: {type: string}}
      responses:
        '200': {description: ok, content: {application/json: {}}}
    post:
      tags: [Merge requests]
      operationId: postApiV4ProjectsIdMergeRequests
      parameters:
      - {in: path, name: id, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/postApiV4ProjectsIdMergeRequests'}
      responses:
        201: {description: created, content: {application/json: {}}}
  /api/v4/projects/{id}/issues:
    get:
      tags: [Issues]
      operationId: getApiV4ProjectsIdIssues
      parameters:
      - {in: path, name: id, required: true, schema: {type: string}}
      - {in: query, name: page, schema: {type: integer}}
      responses:
        '200': {description: ok, content: {application/json: {}}}
  /api/v4/projects/{id}/badges/{badge_id}:
    get:
      tags: [Badges]
      operationId: getApiV4ProjectsIdBadgesBadgeId
      responses:
        '200': {description: ok}
  /api/v4/projects/{id}/badges/render:
    get:
      tags: [Badges]
      operationId: getApiV4ProjectsIdBadgesRender
      responses:
        '200': {description: ok}
  /api/v4/projects/{id}/repository/files/{file_path}:
    get:
      tags: [Repository files]
      operationId: getApiV4ProjectsIdRepositoryFilesFilePath
      responses:
        '200': {description: ok}
    head:
      tags: [Repository files]
      operationId: headApiV4ProjectsIdRepositoryFilesFilePath
      responses:
        '200': {description: ok}
  /api/v4/projects/{id}/uploads:
    post:
      tags: [Projects]
      operationId: postApiV4ProjectsIdUploads
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema: {type: object}
      responses:
        '201': {description: created}
  /api/v4/projects/{id}/archive(/{sha}):
    get:
      tags: [Repositories]
      operationId: getApiV4ProjectsIdArchiveSha
      parameters:
      - {in: path, name: sha, required: false, schema: {type: string}}
      responses:
        '200': {description: ok}
  /api/v4/projects/{id}/(-/)things(/{thing_id}):
    get:
      tags: [Things]
      operationId: getApiV4ProjectsIdDashThingsThingId
      responses:
        '200': {description: ok}
  /api/v4/projects/{id}/odd(:
    get:
      tags: [Projects]
      operationId: getApiV4ProjectsIdOdd
      responses:
        '200': {description: ok}
  /api/v4/groups/{id}/(-/)epics:
    get:
      tags: [Epics]
      operationId: getApiV4GroupsIdDashEpics
      parameters:
      - {in: path, name: id, required: true, schema: {type: string}}
      responses:
        '200': {description: ok}
  /api/v4/projects/{project_id}/packages/nuget/v2/FindPackagesById():
    get:
      tags: [NuGet packages]
      operationId: getApiV4ProjectsProjectIdPackagesNugetV2Findpackagesbyid
      responses:
        '200': {description: ok}
  '/api/v4/projects/{project_id}/packages/nuget/v2/Packages\(\)':
    get:
      tags: [NuGet packages]
      operationId: getApiV4ProjectsProjectIdPackagesNugetV2Packages
      responses:
        '200': {description: ok}
  /api/v4/projects/{id}/packages/helm/{channel}/charts/{file_name}.tgz:
    get:
      tags: [Helm packages]
      operationId: getApiV4ProjectsIdPackagesHelmChannelChartsFileNameTgz
      responses:
        '200': {description: ok}
  /api/v4/jobs/{id}/sbom_scans/{sbom_digest}:
    get:
      tags: [Jobs]
      operationId: getApiV4JobsIdSbomScansSbomScanId
      parameters:
      - {in: path, name: id, required: true, schema: {type: integer}}
      responses:
        '200': {description: ok}
  "/api/v4/projects/{project_id}/packages/nuget/v2/Packages(Id='{package_name}',Version='{package_version}')":
    get:
      tags: [NuGet packages]
      operationId: getApiV4ProjectsProjectIdPackagesNugetV2PackagesidPackageNameVersionPackageVersion
      responses:
        '200': {description: ok}
  /api/v4/projects/{id}/terraform/state/{name}:
    get:
      tags: [Terraform states]
      operationId: getApiV4ProjectsIdTerraformStateName
      responses:
        '200': {description: OK}
        '204': {description: Empty state}
  /api/v4/swagger_doc:
    get:
      operationId: getApiV4SwaggerDoc
      responses:
        '200': {description: ok}
  /api/v4/runners:
    delete:
      tags: [Runners]
      operationId: deleteApiV4Runners
      parameters:
      - {in: query, name: token, required: true, schema: {type: string}}
      responses:
        '204': {description: deleted}
  /api/v4/ai/duo_workflows/revoke_token:
    post:
      tags: [Duo workflows]
      operationId: postApiV4AiDuoWorkflowsRevokeToken
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/postApiV4AiDuoWorkflowsRevokeToken'}
      responses:
        '204': {description: revoked}
components:
  schemas:
    postApiV4ProjectsIdMergeRequests:
      type: object
      required: [source_branch, target_branch, title]
      properties:
        source_branch: {type: string, description: The source branch}
        target_branch: {type: string}
        title: {type: string}
        description: {type: string}
    postApiV4AiDuoWorkflowsRevokeToken:
      type: object
      required: [token]
      properties:
        token: {type: string}
`

func docsFixtureDocs(t *testing.T) *openapidoc.OperationDocs {
	t.Helper()
	d, err := gitlab.DistillDocs([]byte(docsFixture))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

const testEndpoint = "https://gitlab.example:8443"

func lookup(t *testing.T, op string) apiref.Result {
	t.Helper()
	return gitlab.Reference(docsFixtureDocs(t), apiref.Query{Connector: "gitlab", Operation: op}, testEndpoint, nil)
}

func inputNamed(ref *apiref.Reference, name string) (apiref.Input, bool) {
	for _, in := range ref.Inputs {
		if in.Name == name {
			return in, true
		}
	}
	return apiref.Input{}, false
}

func TestDistillDocs_SourceAndVersion(t *testing.T) {
	t.Parallel()
	d := docsFixtureDocs(t)
	sum := sha256.Sum256([]byte(docsFixture))
	if d.Version != "19.5" || d.SHA256 != hex.EncodeToString(sum[:]) || len(d.Ops) != 22 {
		t.Errorf("version %q sha %q ops %d", d.Version, d.SHA256, len(d.Ops))
	}
	if _, ok := d.Ops["getApiV4SwaggerDoc"]; !ok {
		t.Error("an untagged operation with an operationId must still be documented")
	}
}

func TestDistillDocs_SkipsOperationsWithoutID(t *testing.T) {
	t.Parallel()
	d, err := gitlab.DistillDocs([]byte("paths:\n  /api/v4/a:\n    get:\n      tags: [A]\n" +
		"  /api/v4/b:\n    get:\n      operationId: getB\n"))
	if err != nil || len(d.Ops) != 1 {
		t.Fatalf("docs %+v err %v", d, err)
	}
}

func TestDistillDocs_IntResponseCode(t *testing.T) {
	t.Parallel()
	// The fixture writes this operation's 201 unquoted, so YAML decodes the key as an int.
	res := lookup(t, "postApiV4ProjectsIdMergeRequests")
	if res.Reference.Response.Encoding != "json" {
		t.Errorf("response = %+v", res.Reference.Response)
	}
}

func TestDistillDocs_Rejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"malformed YAML":       "paths: [a",
		"NaN has no JSON form": "paths:\n  /api/v4/a:\n    get:\n      operationId: getA\n      x-score: .nan\n",
		// The typed decoder reads info.version as a string; an unquoted 19.10 would also lose its trailing zero.
		"unquoted numeric version": "info:\n  version: 19.10\npaths:\n  /api/v4/a:\n    get:\n      operationId: getA\n",
		"scalar document":          "hello",
		"empty document":           "",
		"no operation ids":         "paths:\n  /api/v4/a:\n    get:\n      tags: [A]\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if d, err := gitlab.DistillDocs([]byte(doc)); !errors.Is(err, openapidoc.ErrDocsRejected) || d != nil {
				t.Errorf("docs %+v err %v", d, err)
			}
		})
	}
}

func TestDocsReference_ProjectLookup(t *testing.T) {
	t.Parallel()
	res := lookup(t, "getApiV4ProjectsId")
	ref := res.Reference
	if res.Outcome != apiref.OutcomeFound || ref.Endpoint != testEndpoint || ref.Method != http.MethodGet ||
		ref.PathTemplate != "/api/v4/projects/{id}" || ref.Connector != "gitlab" || ref.Protocol != "rest-json" ||
		ref.Summary != "Get a single project" || len(ref.FixedHeaders) != 0 {
		t.Fatalf("res = %+v", res)
	}
	id, ok := inputNamed(ref, "id")
	if !ok || id.Type != "string" || !id.Required || !id.Renderable || id.Location != apiref.LocationPath {
		t.Errorf("id = %+v", id)
	}
	wantLimits := []string{
		"the document describes GitLab's master branch; a self-managed instance may run an older version " +
			"that lacks this operation",
		"the docs and the gitlab gate's table can be read from different downloads of the document",
	}
	if !slices.Equal(ref.Limitations, wantLimits) || ref.Pagination.Style != apiref.PaginationUnspecified {
		t.Errorf("limitations %q pagination %+v", ref.Limitations, ref.Pagination)
	}
	want := apiref.Source{
		Name: "gitlab-org/gitlab", Document: "doc/api/openapi/openapi_v3.yaml", Version: "19.5",
		SHA256: docsFixtureDocs(t).SHA256,
	}
	if ref.Source != want {
		t.Errorf("source = %+v", ref.Source)
	}
}

func TestDocsReference_Lookup(t *testing.T) {
	t.Parallel()
	if res := lookup(
		t,
		"nope",
	); res.Outcome != apiref.OutcomeNotFound ||
		res.Reason != `no operation "nope" in gitlab; `+gitlab.DocNameFormat {
		t.Errorf("res = %+v", res)
	}
	if res := lookup(t, "GETAPIV4PROJECTSID"); res.Outcome != apiref.OutcomeFound ||
		res.Reference.Operation != "getApiV4ProjectsId" {
		t.Errorf("res = %+v", res)
	}
}

// TestDocsReference_PrefixedName pins the not_found reason for a name with a GitHub-style "projects/" prefix: a
// weak model guessed the right id with that prefix and looped on a bare not_found until the run stopped it.
func TestDocsReference_PrefixedName(t *testing.T) {
	t.Parallel()
	res := lookup(t, "projects/getApiV4ProjectsIdMergeRequests")
	want := `no operation "projects/getApiV4ProjectsIdMergeRequests" in gitlab; GitLab operation names ` +
		`carry no prefix: did you mean "getApiV4ProjectsIdMergeRequests"?`
	if res.Outcome != apiref.OutcomeNotFound || res.Reason != want || res.Reference != nil {
		t.Errorf("res = %+v", res)
	}
	// A suffix that names no operation falls back to the format sentence.
	res = lookup(t, "projects/getApiV4Nope")
	if res.Reason != `no operation "projects/getApiV4Nope" in gitlab; `+gitlab.DocNameFormat {
		t.Errorf("res = %+v", res)
	}
	// A long name is echoed truncated, so the suggestion and the format sentence always survive the reason bound.
	long := strings.Repeat("a", 600)
	res = lookup(t, long+"/getApiV4ProjectsId")
	if !strings.HasSuffix(res.Reason, `did you mean "getApiV4ProjectsId"?`) {
		t.Errorf("long prefixed name: reason = %q", res.Reason)
	}
	res = lookup(t, long)
	if !strings.HasSuffix(res.Reason, gitlab.DocNameFormat) {
		t.Errorf("long name: reason = %q", res.Reason)
	}
	// Quoting can expand each rune several times over, so the bound applies to the quoted echo.
	res = lookup(t, strings.Repeat("\x00", 200)+"/getApiV4ProjectsId")
	if !strings.HasSuffix(res.Reason, `did you mean "getApiV4ProjectsId"?`) {
		t.Errorf("escaped name: reason = %q", res.Reason)
	}
	// The suffix is matched case-insensitively, like the name itself.
	res = lookup(t, "a/b/GETAPIV4PROJECTSID")
	if !strings.HasSuffix(res.Reason, `did you mean "getApiV4ProjectsId"?`) {
		t.Errorf("res = %+v", res)
	}
}

func TestDocsReference_OffsetPagination(t *testing.T) {
	t.Parallel()
	ref := lookup(t, "getApiV4ProjectsIdMergeRequests").Reference
	want := apiref.Pagination{Style: "offset", InputToken: "page", PageSize: "per_page"}
	limit := `pagination is inferred from the page and per_page query parameters; follow the X-Next-Page ` +
		`response header (or rel="next" in the Link header)`
	if ref.Pagination != want || !slices.Contains(ref.Limitations, limit) {
		t.Errorf("pagination %+v limitations %q", ref.Pagination, ref.Limitations)
	}
	// page alone is not enough.
	if p := lookup(t, "getApiV4ProjectsIdIssues").Reference.Pagination; p.Style != apiref.PaginationUnspecified {
		t.Errorf("issues pagination = %+v", p)
	}
}

func TestDocsReference_Bodies(t *testing.T) {
	t.Parallel()
	res := lookup(t, "postApiV4ProjectsIdMergeRequests")
	ref := res.Reference
	var body []string
	for _, in := range ref.Inputs {
		if in.Location == apiref.LocationBody && in.Required {
			body = append(body, in.Name)
		}
	}
	if res.Outcome != apiref.OutcomeFound || ref.BodyEncoding != apiref.BodyJSON ||
		!slices.Equal(body, []string{"source_branch", "target_branch", "title"}) ||
		!slices.Equal(ref.FixedHeaders, []apiref.Param{{Key: "Content-Type", Value: "application/json"}}) {
		t.Errorf("res = %+v", res)
	}
	up := lookup(t, "postApiV4ProjectsIdUploads")
	if up.Outcome != apiref.OutcomeIncomplete ||
		!slices.Contains(up.Reference.Gaps, "request body is not a JSON object the template can render") {
		t.Errorf("multipart: %+v", up)
	}
}

func TestDocsReference_RefusedInputs(t *testing.T) {
	t.Parallel()
	refuse := func(loc apiref.Location, name string) bool {
		switch loc {
		case apiref.LocationQuery:
			return name == "token" || name == "sudo"
		case apiref.LocationHeader:
			return strings.EqualFold(name, "Private-Token")
		case apiref.LocationBody:
			return name == "token"
		case apiref.LocationPath:
		}
		return false
	}
	ref := func(op string) apiref.Result {
		return gitlab.Reference(docsFixtureDocs(t), apiref.Query{Operation: op}, testEndpoint, refuse)
	}
	for op, gap := range map[string]string{
		"deleteApiV4Runners":                 "required input token is a credential the gitlab connector refuses",
		"postApiV4AiDuoWorkflowsRevokeToken": "required input token is a credential the gitlab connector refuses",
	} {
		res := ref(op)
		if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, []string{gap}) {
			t.Errorf("%s: %+v", op, res)
		}
		if _, ok := inputNamed(res.Reference, "token"); ok {
			t.Errorf("%s: refused input listed", op)
		}
	}
	mr := ref("getApiV4ProjectsIdMergeRequests")
	for _, name := range []string{"sudo", "Private-Token"} {
		if _, ok := inputNamed(mr.Reference, name); ok || mr.Outcome != apiref.OutcomeFound {
			t.Errorf("%s: optional refused input listed or result not found: %+v", name, mr)
		}
	}
}

func TestDocsReference_UnspecifiedResponse(t *testing.T) {
	t.Parallel()
	// The Terraform state GET declares a 200 with no content, yet returns the state file.
	ref := lookup(t, "getApiV4ProjectsIdTerraformStateName").Reference
	limit := "the document does not describe this operation's response format; check the Content-Type response " +
		"header before parsing"
	if ref.Response.Encoding != "unspecified" || !slices.Contains(ref.Limitations, limit) {
		t.Errorf("response %+v limitations %q", ref.Response, ref.Limitations)
	}
	if got := lookup(t, "getApiV4ProjectsId").Reference.Response.Encoding; got != "json" {
		t.Errorf("a described response changed: %q", got)
	}
}

func TestDocsRender_GrapeForms(t *testing.T) {
	t.Parallel()
	d := docsFixtureDocs(t)
	cases := map[string]struct {
		path string
		alt  []string
	}{
		"getApiV4GroupsIdDashEpics": {"/api/v4/groups/{id}/-/epics", []string{"/api/v4/groups/{id}/epics"}},
		"getApiV4ProjectsIdArchiveSha": {
			"/api/v4/projects/{id}/archive/{sha}", []string{"/api/v4/projects/{id}/archive"},
		},
		"getApiV4ProjectsIdDashThingsThingId": {"/api/v4/projects/{id}/-/things/{thing_id}", []string{
			"/api/v4/projects/{id}/-/things", "/api/v4/projects/{id}/things/{thing_id}", "/api/v4/projects/{id}/things",
		}},
		// A group with no "/" is a literal OData call, rendered as documented with no alternative.
		"getApiV4ProjectsProjectIdPackagesNugetV2Findpackagesbyid": {
			"/api/v4/projects/{project_id}/packages/nuget/v2/FindPackagesById()", nil,
		},
		"getApiV4ProjectsProjectIdPackagesNugetV2PackagesidPackageNameVersionPackageVersion": {
			"/api/v4/projects/{project_id}/packages/nuget/v2/Packages(Id='{package_name}',Version='{package_version}')",
			nil,
		},
		// Escaped parentheses are literal too.
		"getApiV4ProjectsProjectIdPackagesNugetV2Packages": {
			"/api/v4/projects/{project_id}/packages/nuget/v2/Packages()", nil,
		},
		// An unbalanced parenthesis stays as written, as the gate's table keeps it.
		"getApiV4ProjectsIdOdd": {"/api/v4/projects/{id}/odd(", nil},
		"getApiV4ProjectsId":    {"/api/v4/projects/{id}", nil},
	}
	for id, want := range cases {
		op := d.Ops[id]
		if op.Path != want.path || !slices.Equal(op.Alt, want.alt) {
			t.Errorf("%s: path %q alt %q", id, op.Path, op.Alt)
		}
	}
}

func TestDocsRender_LabelsAreRequiredPathInputs(t *testing.T) {
	t.Parallel()
	ref := lookup(t, "getApiV4ProjectsIdArchiveSha").Reference
	for _, name := range []string{"id", "sha"} {
		in, ok := inputNamed(ref, name)
		if !ok || !in.Required || in.Location != apiref.LocationPath || in.Type != "string" || !in.Renderable {
			t.Errorf("%s = %+v", name, in)
		}
	}
	ref = lookup(t, "getApiV4JobsIdSbomScansSbomScanId").Reference
	digest, ok := inputNamed(ref, "sbom_digest")
	if !ok || !digest.Required || digest.Type != "string" || digest.Description != "" {
		t.Errorf("undeclared label = %+v", digest)
	}
	if id, _ := inputNamed(ref, "id"); id.Type != "integer" {
		t.Errorf("declared label lost its type: %+v", id)
	}
	// Labels inside a literal OData segment are path inputs too.
	ref = lookup(t, "getApiV4ProjectsProjectIdPackagesNugetV2PackagesidPackageNameVersionPackageVersion").Reference
	for _, name := range []string{"project_id", "package_name", "package_version"} {
		if in, found := inputNamed(ref, name); !found || !in.Required || in.Location != apiref.LocationPath {
			t.Errorf("%s = %+v", name, in)
		}
	}
}

func TestDocsRender_Admission(t *testing.T) {
	t.Parallel()
	const gap = "rendered path is not admitted by the gitlab gate"
	admitted := []string{
		"getApiV4ProjectsId", "getApiV4GroupsIdDashEpics", "getApiV4ProjectsIdArchiveSha",
		"getApiV4ProjectsIdDashThingsThingId", "getApiV4ProjectsProjectIdPackagesNugetV2Packages",
		"getApiV4ProjectsIdOdd",
		"headApiV4ProjectsIdRepositoryFilesFilePath", "getApiV4JobsIdSbomScansSbomScanId",
	}
	for _, id := range admitted {
		if res := lookup(t, id); res.Outcome != apiref.OutcomeFound {
			t.Errorf("%s: %+v", id, res)
		}
	}
	// A label inside a segment never matches the gate's literal segment, and the gate strips the dotted suffix
	// of the last segment; an untagged operation is not in the table at all. The gate reads an unescaped "()" as
	// an empty optional group and registers the path without it, so the literal NuGet paths do not classify.
	for _, id := range []string{
		"getApiV4ProjectsIdPackagesHelmChannelChartsFileNameTgz", "getApiV4SwaggerDoc",
		"getApiV4ProjectsProjectIdPackagesNugetV2Findpackagesbyid",
		"getApiV4ProjectsProjectIdPackagesNugetV2PackagesidPackageNameVersionPackageVersion",
	} {
		if res := lookup(t, id); res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps,
			[]string{gap}) {
			t.Errorf("%s: %+v", id, res)
		}
	}
}

func TestDocsRender_TableRejectionAdmitsNothing(t *testing.T) {
	t.Parallel()
	// No operation is tagged, so the gate's table distiller has no routes and rejects the document.
	d, err := gitlab.DistillDocs([]byte("paths:\n  /api/v4/a:\n    get:\n      operationId: getA\n"))
	if err != nil {
		t.Fatal(err)
	}
	if gaps := d.Ops["getA"].Gaps; !slices.Equal(gaps, []string{"rendered path is not admitted by the gitlab gate"}) {
		t.Errorf("gaps = %q", gaps)
	}
}
