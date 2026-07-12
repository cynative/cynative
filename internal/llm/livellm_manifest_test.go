package llm_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/llm"
)

// The live-LLM manifest is the single source of truth for which providers the
// release-confidence "Live LLM smoke" workflow runs (cynative#50). The workflow
// (.github/workflows/llm-smoke.yaml) turns each enabled row into one matrix job,
// so a malformed row would either silently drop a provider from release coverage
// or break the run. This test is the fail-closed guard: it rides `make test` ->
// the required `Lint & Test` check and the pre-commit `make check-go`, so a bad
// manifest blocks merge rather than surfacing as a red live run later.
//
// The validator lives here (test-only) rather than in shipped code: nothing in
// the cynative binary reads this manifest, so keeping it out of the production
// packages avoids dead surface and the 100% coverage gate while still proving the
// schema fail-closed against crafted-bad inputs below.

// liveLLMRow mirrors one manifest entry. The three flags are *bool so a MISSING
// flag is distinguishable from false (DisallowUnknownFields rejects unknown keys,
// but a decoder leaves an absent known key at its zero value); the validator
// requires all three to be present.
type liveLLMRow struct {
	ID                  string `json:"id"`
	Enabled             *bool  `json:"enabled"`
	Provider            string `json:"provider"`
	Auth                string `json:"auth"`
	Suite               string `json:"suite"`
	ModelVar            string `json:"model_var"`
	RoleVar             string `json:"role_var"`
	Required            *bool  `json:"required"`
	RequireNoConnectors *bool  `json:"require_no_connectors"`
	Note                string `json:"note"`
}

const (
	authGCPWIF  = "gcp-wif"
	authAWSOIDC = "aws-oidc"
	suiteNoTool = "llm-smoke"
	suiteTools  = "llm-tools-smoke"
	// maxRows is a deliberately small cap on live legs (each is a real,
	// credit-spending provider run), far under GitHub's 256-job matrix limit.
	maxRows    = 16
	maxIDLen   = 40
	maxNoteLen = 200
)

// providerAuthAdapter pins each provider to the one credential+env-wiring adapter
// the workflow implements for it: gcp-wif exports only CYNATIVE_LLM_VERTEX_*,
// aws-oidc only CYNATIVE_LLM_BEDROCK_*. Membership in llm.ChatProviders() means
// "chat-capable", not "wired for CI", so a row's (provider, auth) pair must be one
// of these adapters. A genuinely new provider needs a new adapter (a workflow
// job), which is the deliberate non-data case; a same-adapter model (another
// Vertex or Bedrock model id) is a pure manifest edit.
var providerAuthAdapter = map[string]string{ //nolint:gochecknoglobals // stateless test data table.
	"vertex":  authGCPWIF,
	"bedrock": authAWSOIDC,
}

// idPattern and varNamePattern pin the manifest's identifier and variable-name
// shapes. varNamePattern (plus the GITHUB_ guard) matters because a mis-named
// ${{ vars[...] }} silently resolves to "" in Actions rather than erroring, so a
// typo that slips past charset would go unnoticed at run time.
var (
	idPattern      = regexp.MustCompile(`^[a-z0-9-]+$`)
	varNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// validateLiveLLMManifest parses and fully validates the manifest bytes,
// fail-closed: any unknown field, missing flag, unknown enum value, bad
// identifier, or auth/role mismatch is an error. validProviders is the set the
// `provider` field must belong to (the real llm.ChatProviders() catalog for the
// checked-in file; a fixed set for the negative table).
func validateLiveLLMManifest(data []byte, validProviders map[string]bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var rows []liveLLMRow
	if err := dec.Decode(&rows); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	// Reject trailing tokens after the top-level array (strict single-value): a
	// well-formed manifest decodes to exactly one array, so Token() must hit EOF.
	if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
		return errors.New("unexpected trailing data after the manifest array")
	}

	if len(rows) == 0 {
		return errors.New("manifest has no rows")
	}
	if len(rows) > maxRows {
		return fmt.Errorf("manifest has %d rows, exceeding the cap of %d", len(rows), maxRows)
	}

	seen := make(map[string]bool, len(rows))
	for i, r := range rows {
		if err := validateRow(i, r, seen, validProviders); err != nil {
			return err
		}
	}
	return nil
}

// validateRow validates one manifest entry and records its id in seen (so the
// caller detects duplicates). Split out of validateLiveLLMManifest to keep both
// functions under the cognitive-complexity budget.
func validateRow(i int, r liveLLMRow, seen map[string]bool, validProviders map[string]bool) error {
	if !idPattern.MatchString(r.ID) || len(r.ID) > maxIDLen {
		return fmt.Errorf("row %d: id %q must match %s and be <= %d chars", i, r.ID, idPattern, maxIDLen)
	}
	if seen[r.ID] {
		return fmt.Errorf("row %d: duplicate id %q", i, r.ID)
	}
	seen[r.ID] = true

	if r.Enabled == nil {
		return fmt.Errorf("row %q: enabled is required", r.ID)
	}
	if r.Required == nil {
		return fmt.Errorf("row %q: required is required", r.ID)
	}
	if r.RequireNoConnectors == nil {
		return fmt.Errorf("row %q: require_no_connectors is required", r.ID)
	}
	if len(r.Note) > maxNoteLen {
		return fmt.Errorf("row %q: note is %d chars, exceeding %d", r.ID, len(r.Note), maxNoteLen)
	}

	if err := validateRowEnums(r, validProviders); err != nil {
		return err
	}
	if err := validateVarName("model_var", r.ID, r.ModelVar); err != nil {
		return err
	}
	return validateRoleVar(r)
}

// validateRowEnums checks the closed-set fields and their cross-field invariants:
// the provider is chat-capable and its (provider, auth) pair is a wired adapter,
// the suite is a real make target, and require_no_connectors is not set on the
// tools suite (which never reads it, so true there is a silent no-op footgun).
func validateRowEnums(r liveLLMRow, validProviders map[string]bool) error {
	if !validProviders[r.Provider] {
		return fmt.Errorf("row %q: provider %q is not a known chat provider", r.ID, r.Provider)
	}
	if r.Auth != authGCPWIF && r.Auth != authAWSOIDC {
		return fmt.Errorf("row %q: auth %q must be %q or %q", r.ID, r.Auth, authGCPWIF, authAWSOIDC)
	}
	if providerAuthAdapter[r.Provider] != r.Auth {
		return fmt.Errorf("row %q: provider %q is wired for auth %q, not %q",
			r.ID, r.Provider, providerAuthAdapter[r.Provider], r.Auth)
	}
	if r.Suite != suiteNoTool && r.Suite != suiteTools {
		return fmt.Errorf("row %q: suite %q must be %q or %q", r.ID, r.Suite, suiteNoTool, suiteTools)
	}
	if r.Suite == suiteTools && *r.RequireNoConnectors {
		return fmt.Errorf("row %q: require_no_connectors must be false for the %q suite", r.ID, suiteTools)
	}
	return nil
}

// validateRoleVar enforces that role_var is present and valid exactly for the
// aws-oidc family (which needs a role ARN to assume); gcp-wif must not carry one.
func validateRoleVar(r liveLLMRow) error {
	switch r.Auth {
	case authAWSOIDC:
		return validateVarName("role_var", r.ID, r.RoleVar)
	case authGCPWIF:
		if r.RoleVar != "" {
			return fmt.Errorf("row %q: gcp-wif must not set role_var (got %q)", r.ID, r.RoleVar)
		}
	}
	return nil
}

// validateVarName enforces the GitHub-variable-name shape and rejects the
// reserved GITHUB_ prefix (Actions forbids setting GITHUB_*-named variables, so
// such a name could never resolve).
func validateVarName(field, id, name string) error {
	if !varNamePattern.MatchString(name) {
		return fmt.Errorf("row %q: %s %q must match %s", id, field, name, varNamePattern)
	}
	if strings.HasPrefix(name, "GITHUB_") {
		return fmt.Errorf("row %q: %s %q must not use the reserved GITHUB_ prefix", id, field, name)
	}
	return nil
}

// manifestPath resolves .github/live-llm-manifest.json from this test file's
// location, so `go test` works regardless of the invoking directory (mirrors
// providersdocs_test.go).
func manifestPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/llm/livellm_manifest_test.go -> repo root is two dirs up.
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, ".github", "live-llm-manifest.json")
}

// chatProviderSet is the real chat-provider catalog as a lookup set, so the
// manifest's provider ids stay pinned to what cynative can actually run.
func chatProviderSet() map[string]bool {
	m := make(map[string]bool)
	for _, p := range llm.ChatProviders() {
		m[string(p)] = true
	}
	return m
}

func TestLiveLLMManifest_CheckedInFileValidates(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(manifestPath(t))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if verr := validateLiveLLMManifest(data, chatProviderSet()); verr != nil {
		t.Fatalf("checked-in manifest is invalid: %v", verr)
	}

	var rows []liveLLMRow
	if uerr := json.Unmarshal(data, &rows); uerr != nil {
		t.Fatalf("unmarshal manifest: %v", uerr)
	}

	// Golden: the Vertex + Bedrock starters are still present (guards against an
	// accidental deletion that would silently drop release coverage), and both
	// auth families are exercised (so the two-family workflow keeps both jobs live).
	ids := make(map[string]bool, len(rows))
	auths := make(map[string]bool, len(rows))
	for _, r := range rows {
		ids[r.ID] = true
		auths[r.Auth] = true
	}
	for _, want := range []string{"vertex-notool", "vertex-tools", "bedrock-notool"} {
		if !ids[want] {
			t.Errorf("manifest is missing starter row %q", want)
		}
	}
	for _, want := range []string{authGCPWIF, authAWSOIDC} {
		if !auths[want] {
			t.Errorf("manifest has no %q row; both auth families must stay covered", want)
		}
	}
}

func TestLiveLLMManifest_AcceptsValid(t *testing.T) {
	t.Parallel()

	providers := map[string]bool{"vertex": true, "bedrock": true}
	valid := `[
	  {"id":"vertex-notool","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_VERTEX_MODEL","required":true,"require_no_connectors":true,"note":"ok"},
	  {"id":"bedrock-notool","enabled":true,"provider":"bedrock","auth":"aws-oidc","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_BEDROCK_MODEL","role_var":"CYNATIVE_CLI_CI_AWS_ROLE","required":false,"require_no_connectors":true}
	]`
	if err := validateLiveLLMManifest([]byte(valid), providers); err != nil {
		t.Fatalf("expected valid manifest to pass, got: %v", err)
	}
}

func TestLiveLLMManifest_RejectsInvalid(t *testing.T) {
	t.Parallel()

	providers := map[string]bool{"vertex": true, "bedrock": true}
	// Each case is a full manifest that must be rejected for exactly one reason.
	cases := map[string]string{
		"unknown field": `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true,"bogus":1}]`,
		"trailing data": `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}] junk`,
		"empty array":   `[]`,
		"not an array":  `{"id":"a"}`,
		"bad id":        `[{"id":"Bad_ID","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		"duplicate id": `[
		  {"id":"dup","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true},
		  {"id":"dup","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-tools-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}
		]`,
		"unknown provider":     `[{"id":"a","enabled":true,"provider":"nope","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		"bad auth":             `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-oidc","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		"uppercased auth":      `[{"id":"a","enabled":true,"provider":"vertex","auth":"GCP-WIF","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		"bad suite":            `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-run","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		"lowercase model_var":  `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"cynative_model","required":true,"require_no_connectors":true}]`,
		"github model_var":     `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"GITHUB_MODEL","required":true,"require_no_connectors":true}]`,
		"aws missing role_var": `[{"id":"a","enabled":true,"provider":"bedrock","auth":"aws-oidc","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		"gcp with role_var":    `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","role_var":"CYNATIVE_CLI_CI_AWS_ROLE","required":true,"require_no_connectors":true}]`,
		"missing enabled":      `[{"id":"a","provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		"missing required":     `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","require_no_connectors":true}]`,
		"missing rnc":          `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true}]`,
		"null required":        `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":null,"require_no_connectors":true}]`,
		"null manifest":        `null`,
		"long id":              `[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		// provider is chat-capable but its (provider, auth) pair is not a wired adapter.
		"vertex with aws auth":  `[{"id":"a","enabled":true,"provider":"vertex","auth":"aws-oidc","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","role_var":"CYNATIVE_CLI_CI_AWS_ROLE","required":true,"require_no_connectors":true}]`,
		"bedrock with gcp auth": `[{"id":"a","enabled":true,"provider":"bedrock","auth":"gcp-wif","suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
		// require_no_connectors is a silent no-op on the tools suite, so true is rejected.
		"tools with require_no_connectors": `[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-tools-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateLiveLLMManifest([]byte(body), providers); err == nil {
				t.Errorf("expected rejection for %q, got nil", name)
			}
		})
	}
}

func TestLiveLLMManifest_RejectsBounds(t *testing.T) {
	t.Parallel()

	providers := map[string]bool{"vertex": true, "bedrock": true}
	row := func(id string) string {
		return fmt.Sprintf(`{"id":%q,"enabled":true,"provider":"vertex","auth":"gcp-wif",`+
			`"suite":"llm-smoke","model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true}`, id)
	}

	// More than maxRows enabled rows is rejected (bounds live token cost).
	rows := make([]string, 0, maxRows+1)
	for i := 0; i <= maxRows; i++ {
		rows = append(rows, row(fmt.Sprintf("row-%d", i)))
	}
	tooMany := "[" + strings.Join(rows, ",") + "]"
	if err := validateLiveLLMManifest([]byte(tooMany), providers); err == nil {
		t.Errorf("expected rejection of %d rows (cap %d), got nil", maxRows+1, maxRows)
	}

	// A note longer than maxNoteLen is rejected.
	longNote := fmt.Sprintf(`[{"id":"a","enabled":true,"provider":"vertex","auth":"gcp-wif","suite":"llm-smoke",`+
		`"model_var":"CYNATIVE_CLI_CI_X","required":true,"require_no_connectors":true,"note":%q}]`,
		strings.Repeat("x", maxNoteLen+1))
	if err := validateLiveLLMManifest([]byte(longNote), providers); err == nil {
		t.Errorf("expected rejection of an over-length note, got nil")
	}
}
