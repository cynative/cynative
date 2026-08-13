package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cynative/cynative/internal/agentcatalog"
	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/config"
)

// agentMapFS returns a project-tier catalog holding one valid agent.
func agentMapFS(name, desc, body string) fstest.MapFS {
	src := "---\ndescription: " + desc + "\n---\n" + body + "\n"

	return fstest.MapFS{name + ".md": {Data: []byte(src)}} //nolint:exhaustruct // Mode defaults.
}

func catalogOver(fsys fstest.MapFS) func() (*agentcatalog.Catalog, func(), error) {
	return func() (*agentcatalog.Catalog, func(), error) {
		return agentcatalog.New(agentcatalog.Root{
			Source: agentcatalog.SourceUser, FS: fsys, DisplayPath: "/home/u/.cynative/agents",
		}), func() {}, nil
	}
}

func TestJoinTask_FencesBareStdinUnderAgent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		arg      string
		stdin    string
		hasAgent bool
		fenced   bool
	}{
		{"bare stdin without an agent is the trusted task", "", "data", false, false},
		{"bare stdin WITH an agent is fenced", "", "data", true, true},
		{"arg plus stdin is fenced either way", "task", "data", false, true},
		{"arg plus stdin with an agent is fenced", "task", "data", true, true},
		{"no stdin is never fenced", "task", "", true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := joinTask(tc.arg, tc.stdin, false, tc.hasAgent)
			if fenced := strings.Contains(got, "<piped_input>"); fenced != tc.fenced {
				t.Fatalf("joinTask() = %q; fenced = %v, want %v", got, fenced, tc.fenced)
			}
		})
	}
}

// Bare stdin under an agent is fenced with no leading blank lines, and the
// truncation marker still lands outside the fence.
func TestJoinTask_AgentBareStdinExactShape(t *testing.T) {
	t.Parallel()

	got := joinTask("", "  data  ", true, true)

	if !strings.HasPrefix(got, "<piped_input>") {
		t.Fatalf("joinTask() = %q, want no leading blank lines before the fence", got)
	}
	if !strings.HasSuffix(got, stdinTruncationMarker) {
		t.Fatalf("joinTask() = %q, want the truncation marker appended outside the fence", got)
	}
	if !strings.Contains(got, "</piped_input>") {
		t.Fatalf("joinTask() = %q, want a closed fence", got)
	}
}

func TestResolveInvocation_AgentSatisfiesTheTaskRequirement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hasAgent bool
		wantErr  bool
	}{
		{"print mode with no task and no agent fails", false, true},
		{"print mode with no task but an agent succeeds", true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := resolveInvocation(invocationInputs{ //nolint:exhaustruct // defaults exercise the gate.
				printMode:   true,
				autoApprove: true,
				hasAgent:    tc.hasAgent,
			})
			if tc.wantErr && err == nil {
				t.Fatal("resolveInvocation() = nil error, want ErrNoTask")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("resolveInvocation() = %v, want nil", err)
			}
		})
	}
}

func TestBuildRunRequest_TaskIsAlwaysComposed(t *testing.T) {
	t.Parallel()

	def := agentcatalog.Definition{ //nolint:exhaustruct // only the composed fields matter.
		Name:        "a",
		Description: "desc",
		Body:        "body",
	}

	req := buildRunRequest("user text", &def)

	if !strings.HasPrefix(req.Task, "agent description:") {
		t.Fatalf("Task = %q, want the composed text", req.Task)
	}
	if !strings.Contains(req.Task, "user instruction:\nuser text") {
		t.Fatalf("Task = %q, want the user instruction folded in", req.Task)
	}
	if req.Agent == nil || req.Agent.Def.Name != "a" {
		t.Fatal("the selected definition must travel with the request")
	}
}

func TestBuildRunRequest_WithoutAgentPassesTaskThrough(t *testing.T) {
	t.Parallel()

	req := buildRunRequest("plain task", nil)

	if req.Task != "plain task" {
		t.Fatalf("Task = %q, want the raw task unchanged", req.Task)
	}
	if req.Agent != nil {
		t.Fatal("Agent must be nil when none was selected")
	}
}

func TestAgentSelection_Provenance(t *testing.T) {
	t.Parallel()

	raw := []byte("---\ndescription: d\n---\nbody\n")
	sel := &agentSelection{Def: agentcatalog.Definition{ //nolint:exhaustruct // only stamped fields matter.
		Name:   "a",
		Source: agentcatalog.SourceUser,
		Raw:    raw,
	}}

	got := sel.provenance()

	sum := sha256.Sum256(raw)
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %q, want the digest of the exact raw bytes", got.SHA256)
	}
	if got.Name != "a" || got.Source != "user" {
		t.Errorf("provenance = %+v, want name a and source user", got)
	}
}

func TestRenderAgentProvenance(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	sel := &agentSelection{Def: agentcatalog.Definition{ //nolint:exhaustruct // only rendered fields matter.
		Name:   "pub\x1b[31mexposure",
		Source: agentcatalog.SourceUser,
		Path:   "/home/u/.cynative/agents/a.md",
	}}

	renderAgentProvenance(&buf, sel)

	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("provenance line carries a terminal escape: %q", out)
	}
	if !strings.Contains(out, "user") || !strings.Contains(out, "/home/u/.cynative/agents/a.md") {
		t.Fatalf("provenance line = %q, want the tier and path", out)
	}
}

func TestRenderAgentProvenance_NilIsSilent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	renderAgentProvenance(&buf, nil)

	if buf.Len() != 0 {
		t.Fatalf("renderAgentProvenance(nil) wrote %q, want nothing", buf.String())
	}
}

// --agent= must be an ErrAgentName, and it must be reported BEFORE the
// no-terminal check and before stdin is drained: otherwise a bad flag value is
// masked by ErrNoApprovalTerminal, or blocks on a non-closing pipe.
func TestRunRoot_AgentValidatedBeforeTerminalCheckAndStdin(t *testing.T) {
	t.Parallel()

	drained := false

	d := testDeps()
	d.hasTerminal = false
	d.stdinIsTTY = false
	d.readStdin = func() (string, bool, error) {
		drained = true

		return "", false, nil
	}
	d.agentName = "" // --agent= : flag changed, value empty
	d.agentFlagChanged = true

	err := d.runRoot(t.Context(), nil, true, researchFlags{}) //nolint:exhaustruct // defaults are fine.

	if !errors.Is(err, agentcatalog.ErrAgentName) {
		t.Fatalf("runRoot() = %v, want ErrAgentName ahead of ErrNoApprovalTerminal", err)
	}
	if drained {
		t.Error("stdin was drained before the agent name was rejected")
	}
}

func TestRunRoot_NoAgentNeverOpensTheCatalog(t *testing.T) {
	t.Parallel()

	opened := false

	d := testDeps()
	d.openAgentCatalog = func() (*agentcatalog.Catalog, func(), error) {
		opened = true

		return agentcatalog.New(), func() {}, nil
	}
	d.run = func(context.Context, runRequest, config.Config, researchFlags) error { return nil }

	//nolint:exhaustruct // defaults are fine.
	if err := d.runRoot(t.Context(), []string{"a task"}, true, researchFlags{}); err != nil {
		t.Fatalf("runRoot() = %v", err)
	}
	if opened {
		t.Error("a run naming no agent must not open the catalog")
	}
}

func TestRunRoot_ComposesAndCleansUp(t *testing.T) {
	t.Parallel()

	cleaned := false

	d := testDeps()
	d.agentName = "a"
	d.agentFlagChanged = true
	d.openAgentCatalog = func() (*agentcatalog.Catalog, func(), error) {
		return agentcatalog.New(agentcatalog.Root{
			Source:      agentcatalog.SourceUser,
			FS:          agentMapFS("a", "desc", "body"),
			DisplayPath: "/home/u/.cynative/agents",
		}), func() { cleaned = true }, nil
	}

	var got runRequest

	d.run = func(_ context.Context, req runRequest, _ config.Config, _ researchFlags) error {
		got = req

		return nil
	}

	//nolint:exhaustruct // defaults are fine.
	if err := d.runRoot(t.Context(), nil, true, researchFlags{}); err != nil {
		t.Fatalf("runRoot() = %v", err)
	}
	if !strings.HasPrefix(got.Task, "agent description:\ndesc") {
		t.Fatalf("Task = %q, want the composed prompt", got.Task)
	}
	if got.Agent == nil || got.Agent.Def.Name != "a" {
		t.Fatal("the selection must travel with the request")
	}
	if !cleaned {
		t.Error("the catalog cleanup was not run")
	}
}

func TestRunRoot_UnknownAgentListsAvailableNames(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.agentName = "missing"
	d.agentFlagChanged = true
	d.openAgentCatalog = catalogOver(agentMapFS("known", "d", "body"))

	err := d.runRoot(t.Context(), nil, true, researchFlags{}) //nolint:exhaustruct // defaults are fine.
	if !errors.Is(err, agentcatalog.ErrAgentNotFound) {
		t.Fatalf("runRoot() = %v, want ErrAgentNotFound", err)
	}
	if !strings.Contains(err.Error(), "known") {
		t.Fatalf("error %q should list the available agents", err)
	}
}

// A malformed winner surfaces as ErrAgentInvalid, unannotated: listing
// alternatives would imply the name was not found, when in fact it was found
// and is broken.
func TestRunRoot_MalformedAgentIsNotAnnotated(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{"a.md": {Data: []byte("no frontmatter")}} //nolint:exhaustruct // Mode defaults.

	d := testDeps()
	d.agentName = "a"
	d.agentFlagChanged = true
	d.openAgentCatalog = catalogOver(fsys)

	err := d.runRoot(t.Context(), nil, true, researchFlags{}) //nolint:exhaustruct // defaults are fine.
	if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
		t.Fatalf("runRoot() = %v, want ErrAgentInvalid", err)
	}
	if strings.Contains(err.Error(), "available agents") {
		t.Fatalf("a malformed winner must not be annotated as not-found: %v", err)
	}
}

func TestRunRoot_CatalogOpenFailureSurfaces(t *testing.T) {
	t.Parallel()

	d := testDeps()
	d.agentName = "a"
	d.agentFlagChanged = true
	d.openAgentCatalog = func() (*agentcatalog.Catalog, func(), error) {
		return nil, nil, errors.New("boom")
	}

	err := d.runRoot(t.Context(), nil, true, researchFlags{}) //nolint:exhaustruct // defaults are fine.
	if err == nil || !strings.Contains(err.Error(), "open agent sources") {
		t.Fatalf("runRoot() = %v, want the catalog open failure surfaced", err)
	}
}

// failReadDirFS makes Names() fail after the catalog opened successfully.
type failReadDirFS struct{ fstest.MapFS }

func (failReadDirFS) ReadDir(string) ([]fs.DirEntry, error) {
	return nil, errors.New("enumeration failed")
}

// When the available-name list cannot be produced, the original not-found error
// is returned rather than a partial or misleading suggestion list.
func TestAnnotateResolveError_NamesFailureReturnsOriginal(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(agentcatalog.Root{
		Source:      agentcatalog.SourceUser,
		FS:          failReadDirFS{},
		DisplayPath: "/home/u/.cynative/agents", //nolint:exhaustruct // empty MapFS.
	})

	got := annotateResolveError(agentcatalog.ErrAgentNotFound, c)
	if !errors.Is(got, agentcatalog.ErrAgentNotFound) {
		t.Fatalf("annotateResolveError() = %v, want the original error", got)
	}
	if strings.Contains(got.Error(), "available agents") {
		t.Fatalf("error %q must not claim a name list it could not build", got)
	}
}

// With no agents at all there is nothing to suggest, so no suffix is added.
func TestAnnotateResolveError_EmptyNamesAddsNoSuffix(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(agentcatalog.Root{
		Source: agentcatalog.SourceUser, FS: fstest.MapFS{}, DisplayPath: "/home/u/.cynative/agents",
	})

	got := annotateResolveError(agentcatalog.ErrAgentNotFound, c)
	if strings.Contains(got.Error(), "available agents") {
		t.Fatalf("error %q should add no suffix when there are no agents", got)
	}
}

// A non-not-found error passes through untouched: listing alternatives would
// imply the name was missing when it was found and unusable.
func TestAnnotateResolveError_NonNotFoundPassesThrough(t *testing.T) {
	t.Parallel()

	c := agentcatalog.New(agentcatalog.Root{
		Source: agentcatalog.SourceUser, FS: agentMapFS("known", "d", "b"), DisplayPath: "/home/u/.cynative/agents",
	})

	got := annotateResolveError(agentcatalog.ErrAgentInvalid, c)
	if got.Error() != agentcatalog.ErrAgentInvalid.Error() {
		t.Fatalf("annotateResolveError() = %v, want the error unchanged", got)
	}
}

// The provenance line reaches stderr and the audit stamp reaches the sink
// factory, which is the only place the two cross into runResearch.
func TestRunResearch_RendersProvenanceAndStampsAudit(t *testing.T) {
	t.Parallel()

	var errBuf bytes.Buffer

	var gotProv *audit.AgentProvenance

	d := testDeps()
	d.errOut = &errBuf
	d.newAuditSink = func(_ config.Config, prov *audit.AgentProvenance) (audit.Sink, func() error, error) {
		gotProv = prov

		return nil, func() error { return nil }, nil
	}

	raw := []byte("---\ndescription: desc\n---\nbody\n")
	req := runRequest{
		Task: "composed",
		Agent: &agentSelection{Def: agentcatalog.Definition{ //nolint:exhaustruct // only stamped fields matter.
			Name:   "a",
			Source: agentcatalog.SourceUser,
			Path:   "/home/u/.cynative/agents/a.md",
			Raw:    raw,
		}},
	}

	//nolint:exhaustruct // defaults
	if err := d.runResearch(t.Context(), req, validCfg(), researchFlags{}); err != nil {
		t.Fatalf("runResearch() = %v", err)
	}

	if !strings.Contains(errBuf.String(), "Agent: a") {
		t.Errorf("stderr = %q, want the provenance line", errBuf.String())
	}
	if gotProv == nil {
		t.Fatal("the audit sink was built without provenance")
	}

	sum := sha256.Sum256(raw)
	if gotProv.SHA256 != hex.EncodeToString(sum[:]) || gotProv.Source != "user" {
		t.Errorf("provenance = %+v, want the raw-bytes digest and the user tier", gotProv)
	}
}

// closableFS models a catalog backed by real OS handles: once its cleanup runs,
// enumeration through it fails. A no-op cleanup over a MapFS cannot express
// that, which is why the ordering bug below was invisible to the other tests.
type closableFS struct {
	fstest.MapFS

	closed *bool
}

func (f closableFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if *f.closed {
		return nil, errors.New("file already closed")
	}

	return f.MapFS.ReadDir(name)
}

// The available-agents list must be built BEFORE the catalog is released.
// selectAgent originally called cleanup() first, which closed the [os.Root]
// handles that annotateResolveError enumerates through, so the suggestion list
// was silently dropped on every real run while the fake-cleanup tests passed.
func TestSelectAgent_AnnotatesBeforeReleasingTheCatalog(t *testing.T) {
	t.Parallel()

	closed := false

	d := testDeps()
	d.agentName = "missing"
	d.agentFlagChanged = true
	d.openAgentCatalog = func() (*agentcatalog.Catalog, func(), error) {
		fsys := closableFS{MapFS: agentMapFS("known", "d", "body"), closed: &closed}

		return agentcatalog.New(agentcatalog.Root{
			Source: agentcatalog.SourceUser, FS: fsys, DisplayPath: "/home/u/.cynative/agents",
		}), func() { closed = true }, nil
	}

	_, _, err := d.selectAgent()
	if !errors.Is(err, agentcatalog.ErrAgentNotFound) {
		t.Fatalf("selectAgent() = %v, want ErrAgentNotFound", err)
	}
	if !strings.Contains(err.Error(), "known") {
		t.Fatalf("error %q lost the available-agents list: it was built after cleanup", err)
	}
	if !closed {
		t.Error("the catalog must still be released on the error path")
	}
}
