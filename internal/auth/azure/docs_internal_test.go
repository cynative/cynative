package azure

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/apiref"
)

// fakeSpecs is a specSource over an in-memory index.
type fakeSpecs struct {
	*specFakeFiles

	ix         *Index
	indexErr   error
	summaryErr map[string]error
	onSummary  func()                    // when set, runs inside every Summary call
	onIndex    func(ctx context.Context) // when set, runs inside every Index call
	mu         sync.Mutex
	summaries  map[string]int
	indexCalls int
}

func (f *fakeSpecs) Index(ctx context.Context) (*Index, error) {
	f.mu.Lock()
	f.indexCalls++
	f.mu.Unlock()
	if f.onIndex != nil {
		f.onIndex(ctx)
	}

	return f.ix, f.indexErr
}

func (f *fakeSpecs) indexCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.indexCalls
}

func (f *fakeSpecs) Summary(ctx context.Context, _ string, file IndexFile, b *Budget) (*FileSummary, error) {
	f.mu.Lock()
	f.summaries[file.Path]++
	err := f.summaryErr[file.Path]
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// Like a warm cache, the fake ignores the context, so the lookup's own checks are what the tests prove.
	if f.onSummary != nil {
		f.onSummary()
	}
	body, _ := f.File(context.WithoutCancel(ctx), "", file)
	if err = b.Charge(int64(len(body))); err != nil {
		return nil, err
	}

	return Summarize(body)
}

func (f *fakeSpecs) summaryCount(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.summaries[p]
}

// fixtureFile is one spec file of the fixture namespace Microsoft.Test: group "test/<service>", a kind, a dir.
type fixtureFile struct {
	service, kind, dir, name, body string
}

func (f fixtureFile) path() string {
	return "specification/test/resource-manager/Microsoft.Test/" + f.service + "/" + f.kind + "/" + f.dir + "/" + f.name
}

// specFixture builds a fakeSpecs whose index holds exactly files, with Dirs sorted as BuildIndex sorts them.
func specFixture(files ...fixtureFile) *fakeSpecs {
	bodies := map[string]string{commonFile: renderCommon}
	groups := map[string]*IndexGroup{}
	refs := map[string]string{commonFile: fmt.Sprintf("%040x", 0)}
	for i, f := range files {
		bodies[f.path()] = f.body
		refs[f.path()] = fmt.Sprintf("%040x", i+1)
		g := groups["test/"+f.service]
		if g == nil {
			g = &IndexGroup{}
			groups["test/"+f.service] = g
		}
		at := slices.IndexFunc(g.Dirs, func(d IndexDir) bool { return d.Kind == f.kind && d.Name == f.dir })
		if at < 0 {
			g.Dirs = append(g.Dirs, IndexDir{Kind: f.kind, Name: f.dir})
			at = len(g.Dirs) - 1
		}
		g.Dirs[at].Files = append(g.Dirs[at].Files, IndexFile{Path: f.path(), Blob: refs[f.path()]})
	}
	for _, g := range groups {
		slices.SortFunc(g.Dirs, func(a, b IndexDir) int {
			if c := strings.Compare(b.Name, a.Name); c != 0 {
				return c
			}

			return kindRank(a.Kind) - kindRank(b.Kind)
		})
	}
	ix := &Index{SHA: specTestSHA, Refs: refs, Namespaces: map[string]*IndexNamespace{
		"microsoft.test": {Name: "Microsoft.Test", Groups: groups},
	}}

	return &fakeSpecs{
		specFakeFiles: newSpecFakeFiles(bodies), ix: ix, summaryErr: map[string]error{},
		summaries: map[string]int{},
	}
}

// specOps is a spec file of version whose paths hold one GET per id, each at /…/things/<id>.
func specOps(version string, ids ...string) string {
	var members []string
	for _, id := range ids {
		members = append(members, fmt.Sprintf(`%q:{"get":{"operationId":%q,"parameters":[%s,%s]}}`,
			"/subscriptions/{subscriptionId}/providers/Microsoft.Test/things/"+id, id, pSub, pVersion))
	}

	return `{"info":{"version":"` + version + `"},"paths":{` + strings.Join(members, ",") + `}}`
}

func lookup(t *testing.T, f *fakeSpecs, op, model string) apiref.Result {
	t.Helper()
	d := NewDocs(f, "https://management.azure.com", func() Catalog { return nil })

	return d.Reference(context.Background(), apiref.Query{
		Connector: "azure", Service: "Microsoft.Test",
		Operation: op, Model: model,
	})
}

func TestDocsReference_QueryGrammar(t *testing.T) {
	t.Parallel()
	f := specFixture()
	d := NewDocs(f, "https://management.azure.com", func() Catalog { return nil })
	long := strings.Repeat(`"\`, 400)
	for _, q := range []apiref.Query{
		{Operation: "X"},
		{Service: "compute", Operation: "X"},
		{Service: long, Operation: "X"},
		{Service: "Microsoft.Test", Model: "latest", Operation: "X"},
		{Service: "Microsoft.Test", Model: long, Operation: "X"},
		{Service: "Microsoft.Test", Model: "test/Test@beta/2024-01-01", Operation: "X"},
		{Service: "Microsoft.Test", Model: "test/Test@stable/now", Operation: "X"},
		{Service: "Microsoft.Test", Model: "a/b/c@stable/2024-01-01", Operation: "X"},
		{Service: "Microsoft.Test", Model: "test/Test@stable/2024-01-01/../x.json", Operation: "X"},
		{Service: "Microsoft.Test", Model: "test/Test@stable/2024-01-01/x.yaml", Operation: "X"},
		{Service: "Microsoft.Test", Model: "test/Test@stable", Operation: "X"},
		{Service: "Microsoft.Test", Model: "noat", Operation: "X"},
	} {
		res := d.Reference(context.Background(), q)
		if res.Outcome != apiref.OutcomeNotFound || utf8.RuneCountInString(res.Reason) > apiref.MaxReason {
			t.Errorf("%+v = %s %q", q, res.Outcome, res.Reason)
		}
		if !strings.HasSuffix(res.Reason, "Microsoft.Compute") && !strings.Contains(res.Reason, "an ambiguous result") {
			t.Errorf("%+v: the guidance did not survive: %q", q, res.Reason)
		}
	}
	if n := f.summaryCount(commonFile); n != 0 || len(f.calls) != 0 || f.indexCount() != 0 {
		t.Errorf("a refused query read %d summaries, %d files and %d indexes", n, len(f.calls), f.indexCount())
	}
}

func TestParseSelector(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]selector{
		"test/Test@stable/2024-01-01": {group: "test/Test", kind: "stable", dir: "2024-01-01"},
		"test@preview/2024-01-01-preview/a.json": {
			group: "test", kind: "preview", dir: "2024-01-01-preview",
			file: "a.json",
		},
	} {
		got, ok := parseSelector(s)
		if !ok || got != want || got.String() != s {
			t.Errorf("parseSelector(%q) = %+v, %v, String %q", s, got, ok, got.String())
		}
	}
}

func TestDocsReference_IndexAndNamespace(t *testing.T) {
	t.Parallel()
	f := specFixture()
	f.indexErr = errors.New("listing failed: 503")
	if res := lookup(t, f, "X", ""); res.Outcome != apiref.OutcomeUnavailable ||
		!strings.Contains(res.Reason, "listing failed: 503") {
		t.Errorf("index error = %+v", res)
	}
	f = specFixture(fixtureFile{"Test", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")})
	d := NewDocs(f, "https://management.azure.com", func() Catalog { return nil })
	res := d.Reference(context.Background(), apiref.Query{Service: "Microsoft.Missing", Operation: "X"})
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, "no namespace") {
		t.Errorf("missing namespace = %+v", res)
	}
	res = d.Reference(context.Background(), apiref.Query{Service: "microsoft.TEST", Operation: "Things_Get"})
	if res.Outcome != apiref.OutcomeFound {
		t.Errorf("case-insensitive namespace = %+v", res)
	}
}

func TestDocsReference_Passes(t *testing.T) {
	t.Parallel()
	f := specFixture(
		fixtureFile{"Test", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		fixtureFile{"Test", kindStable, "2023-01-01", "a.json", specOps("2023-01-01", "Things_Get", "Old_Get")},
		fixtureFile{"Test", kindStable, "2022-01-01", "a.json", specOps("2022-01-01", "Old_Get", "Older_Get")},
		fixtureFile{"Test", kindPreview, "2025-01-01-preview", "a.json", specOps("2025-01-01-preview", "New_Get")},
		fixtureFile{"Disk", kindStable, "2024-02-01", "d.json", specOps("2024-02-01", "Disks_Get")},
	)
	res := lookup(t, f, "Things_Get", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.APIVersion != "2024-01-01" ||
		res.Reference.Model != "test/Test@stable/2024-01-01" || !slices.Contains(res.Reference.Limitations, gateNotLoaded) {
		t.Fatalf("pass 1 = %+v", res)
	}
	res = lookup(t, f, "Old_Get", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.APIVersion != "2023-01-01" {
		t.Fatalf("pass 2 = %+v", res)
	}
	older := fixtureFile{"Test", kindStable, "2022-01-01", "a.json", ""}.path()
	if n := f.summaryCount(older); n != 0 {
		t.Errorf("pass 2 read the 2022 dir %d times after the 2023 dir defined the operation", n)
	}
	res = lookup(t, f, "New_Get", "")
	if res.Outcome != apiref.OutcomeAmbiguous || fmt.Sprint(res.Choices) != "[test/Test@preview/2025-01-01-preview]" ||
		!strings.Contains(res.Reason, "no stable version") {
		t.Fatalf("pass 3 = %+v", res)
	}
	res = lookup(t, f, "Thingz_Get", "")
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, `"Things_Get"`) {
		t.Fatalf("not found = %+v", res)
	}
	res = lookup(t, f, "things_get", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.Operation != "Things_Get" {
		t.Fatalf("case-insensitive = %+v", res)
	}

	f = specFixture(
		fixtureFile{"Fold", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "widgets_get")},
		fixtureFile{"Fold", kindStable, "2023-01-01", "a.json", specOps("2023-01-01", "Widgets_Get")},
	)
	res = lookup(t, f, "Widgets_Get", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.Operation != "Widgets_Get" ||
		res.Reference.APIVersion != "2023-01-01" {
		t.Fatalf("an exact id in an older dir must outrank a case variant in the newest: %+v", res)
	}
}

func TestDocsReference_Collisions(t *testing.T) {
	t.Parallel()
	same := specOps("2024-01-01", "Operations_List")
	f := specFixture(
		fixtureFile{"A", kindStable, "2024-01-01", "a.json", same},
		fixtureFile{"B", kindStable, "2024-01-01", "b.json", same},
		fixtureFile{"C", kindStable, "2023-01-01", "c.json", specOps("2023-01-01", "Operations_List")},
	)
	res := lookup(t, f, "Operations_List", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.Model != "test/A@stable/2024-01-01" {
		t.Fatalf("identical requests merge to the newest, then the first group: %+v", res)
	}
	f = specFixture(
		fixtureFile{"A", kindStable, "2024-01-01", "a.json", same},
		fixtureFile{"A", kindStable, "2024-01-01", "b.json", same},
	)
	res = lookup(t, f, "Operations_List", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.Model != "test/A@stable/2024-01-01/a.json" {
		t.Fatalf("identical requests in one dir merge to the first file: %+v", res)
	}

	other := strings.Replace(specOps("2024-01-01", "Things_Get"), "things/Things_Get", "other/Things_Get", 1)
	f = specFixture(
		fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		fixtureFile{"A", kindStable, "2024-01-01", "b.json", other},
		fixtureFile{"B", kindStable, "2024-01-01", "x.json", specOps("2024-01-01", "things_get", "THINGS_GET")},
	)
	res = lookup(t, f, "Things_Get", "")
	want := "[test/A@stable/2024-01-01/a.json test/A@stable/2024-01-01/b.json]"
	if res.Outcome != apiref.OutcomeAmbiguous || fmt.Sprint(res.Choices) != want {
		t.Fatalf("differing requests = %+v, want choices %s", res, want)
	}
	res = lookup(t, f, "Things_Get", "test/A@stable/2024-01-01/b.json")
	if res.Outcome != apiref.OutcomeFound || !strings.Contains(res.Reference.PathTemplate, "/other/") ||
		res.Reference.Model != "test/A@stable/2024-01-01/b.json" {
		t.Fatalf("file selector = %+v", res)
	}
	res = lookup(t, f, "THINGS_get", "test/B@stable/2024-01-01")
	if res.Outcome != apiref.OutcomeAmbiguous || fmt.Sprint(res.Choices) != "[THINGS_GET things_get]" {
		t.Fatalf("case variants = %+v", res)
	}

	dup := `{"info":{"version":"2024-01-01"},"paths":{
		"/subscriptions/{subscriptionId}/providers/Microsoft.Test/a":{"get":{"operationId":"Dup","parameters":[` +
		pSub + `,` + pVersion + `]}},
		"/subscriptions/{subscriptionId}/providers/Microsoft.Test/b":{"get":{"operationId":"Dup","parameters":[` +
		pSub + `,` + pVersion + `]}}}}`
	f = specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", dup})
	res = lookup(t, f, "Dup", "")
	if res.Outcome != apiref.OutcomeAmbiguous || !strings.Contains(res.Reason, "one file") {
		t.Fatalf("same file twice = %+v", res)
	}
}

func TestDocsReference_Models(t *testing.T) {
	t.Parallel()
	f := specFixture(
		fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		fixtureFile{"A", kindPreview, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		fixtureFile{"A", kindStable, "2020-01-01", "a.json", specOps("2020-01-01", "Things_Get")},
	)
	if res := lookup(t, f, "Things_Get", "2020-01-01"); res.Outcome != apiref.OutcomeFound ||
		res.Reference.APIVersion != "2020-01-01" {
		t.Fatalf("bare version = %+v", res)
	}
	if res := lookup(t, f, "Things_Get", "2024-01-01"); res.Outcome != apiref.OutcomeFound ||
		res.Reference.Model != "test/A@stable/2024-01-01" {
		t.Fatalf("bare version with a stable and a preview dir = %+v", res)
	}
	if res := lookup(t, f, "Things_Get", "test/A@preview/2024-01-01"); res.Outcome != apiref.OutcomeFound ||
		res.Reference.Model != "test/A@preview/2024-01-01" {
		t.Fatalf("selector = %+v", res)
	}
	res := lookup(t, f, "Things_Get", "2019-01-01")
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, "2024-01-01, 2020-01-01") {
		t.Fatalf("missing version = %+v", res)
	}
	if res = lookup(t, f, "Things_Get", "test/Z@stable/2024-01-01"); res.Outcome != apiref.OutcomeNotFound {
		t.Fatalf("missing selector = %+v", res)
	}
	g := specFixture(fixtureFile{
		"A", kindStable, "2024-01-01", "a.json",
		specOps("2024-01-01", "Things_Get", "things_get"),
	})
	if res = lookup(t, g, "Things_Get", "2024-01-01"); res.Outcome != apiref.OutcomeFound ||
		res.Reference.Operation != "Things_Get" {
		t.Fatalf("an exact id in a model dir must outrank its case variant = %+v", res)
	}
	if res = lookup(t, f, "Nope", "2024-01-01"); res.Outcome != apiref.OutcomeNotFound ||
		strings.Contains(res.Reason, "pass model") {
		t.Fatalf("model not found = %+v", res)
	}
}

func TestDocsReference_Stops(t *testing.T) {
	t.Parallel()
	files := []fixtureFile{
		{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		{"A", kindStable, "2023-01-01", "a.json", specOps("2023-01-01", "Other_Get")},
	}
	f := specFixture(files...)
	d := NewDocs(f, "https://management.azure.com", func() Catalog { return nil })
	d.budget = int64(len(files[0].body) + 1)
	res := d.Reference(context.Background(), apiref.Query{Service: "Microsoft.Test", Operation: "Other_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || !strings.Contains(res.Reason, "budget") ||
		!strings.Contains(res.Reason, `"Things_Get"`) || !strings.Contains(res.Reason, "pass model") {
		t.Fatalf("budget stop = %+v", res)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res = NewDocs(specFixture(files...), "e", func() Catalog { return nil }).Reference(ctx,
		apiref.Query{Service: "Microsoft.Test", Operation: "Things_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || !strings.HasPrefix(res.Reason, "the lookup was interrupted") {
		t.Fatalf("cancelled = %+v", res)
	}
	past, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if got := ContextReason(past); got != "the lookup timed out after 120s" {
		t.Fatalf("deadline reason = %q", got)
	}

	f = specFixture(files...)
	f.summaryErr[files[0].path()] = errors.New("summary failed")
	if res = lookup(t, f, "Things_Get", ""); res.Outcome != apiref.OutcomeUnavailable ||
		!strings.Contains(res.Reason, "summary failed") {
		t.Fatalf("summary error = %+v", res)
	}
	f = specFixture(files...)
	f.fail[files[0].path()] = errors.New("file failed")
	f.summaryErr = map[string]error{}
	res = NewDocs(&summaryOnly{f}, "e", func() Catalog { return nil }).Reference(context.Background(),
		apiref.Query{Service: "Microsoft.Test", Operation: "Things_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || !strings.Contains(res.Reason, "file failed") {
		t.Fatalf("file error = %+v", res)
	}
	broken := strings.Replace(specOps("2024-01-01", "Things_Get"), `"get":{`,
		`"get":{"x-ms-long-running-operation":"yes",`, 1)
	res = lookup(t, specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", broken}), "Things_Get", "")
	if res.Outcome != apiref.OutcomeUnavailable {
		t.Fatalf("render error = %+v", res)
	}
}

// summaryOnly serves summaries from a body the file read then refuses, so the render's own read fails.
type summaryOnly struct{ *fakeSpecs }

func (s *summaryOnly) Summary(ctx context.Context, _ string, file IndexFile, b *Budget) (*FileSummary, error) {
	body := s.bodies[file.Path]
	if err := b.Charge(int64(len(body))); err != nil {
		return nil, err
	}
	_ = ctx

	return Summarize(body)
}

// TestDocsReference_Finish pins the one exit with no catalog in memory, where the gate check answers gateNotLoaded
// for a nil snapshot. NewDocs keeping the getter is pinned separately, without calling finish on a zero catalog the
// check could not read.
func TestDocsReference_Finish(t *testing.T) {
	t.Parallel()
	snap := &catalog{}
	if d := NewDocs(specFixture(), "https://management.azure.com", func() Catalog { return snap }); d.gate() != snap {
		t.Fatalf("NewDocs did not keep the gate snapshot getter")
	}
	d := NewDocs(specFixture(), "https://management.azure.com", func() Catalog { return nil })
	res := d.finish(context.Background(), &apiref.Reference{Gaps: []string{"g"}})
	if res.Outcome != apiref.OutcomeIncomplete || !slices.Contains(res.Reference.Limitations, gateNotLoaded) {
		t.Fatalf("finish = %+v", res)
	}
}

// TestDocsReference_CancelAfterTheSearch pins the render's own context check: the context is cancelled while the
// last summary is read, so the search finishes and only the render can notice, before it reads the file. The one
// read the fake counts is the summary's own.
func TestDocsReference_CancelAfterTheSearch(t *testing.T) {
	t.Parallel()
	files := []fixtureFile{{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")}}
	f := specFixture(files...)
	ctx, cancel := context.WithCancel(context.Background())
	f.onSummary = cancel
	res := NewDocs(f, "e", func() Catalog { return nil }).Reference(ctx,
		apiref.Query{Service: "Microsoft.Test", Operation: "Things_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || !strings.HasPrefix(res.Reason, "the lookup was interrupted") {
		t.Fatalf("cancelled after the search = %+v", res)
	}
	if n := f.count(files[0].path()); n != 1 {
		t.Errorf("the file was read %d times, want 1 (the summary's read, none by the render)", n)
	}
}

// cancelOnRender cancels a context when the render reads a file, then serves it: Summary reads through the
// embedded fake and never reaches this File.
type cancelOnRender struct {
	*fakeSpecs

	cancel context.CancelFunc
}

func (c *cancelOnRender) File(ctx context.Context, sha string, f IndexFile) ([]byte, error) {
	c.cancel()

	return c.fakeSpecs.File(ctx, sha, f)
}

// TestDocsReference_CancelledLookupsAnswerUnavailable pins the check at the lookup's exit: a lookup whose context
// ends during its last summary read or its last file read answers unavailable, never the outcome it had reached.
func TestDocsReference_CancelledLookupsAnswerUnavailable(t *testing.T) {
	t.Parallel()
	stable := func(ids ...string) fixtureFile {
		return fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", ids...)}
	}
	cases := map[string]struct {
		file     fixtureFile
		op       string
		atCall   int32 // the summary call that cancels; 0 cancels on the render's file read
		original apiref.Outcome
	}{
		"last preview summary": {
			fixtureFile{"A", kindPreview, "2024-01-01-preview", "a.json", specOps("2024-01-01-preview", "New_Get")},
			"New_Get", 1, apiref.OutcomeAmbiguous,
		},
		"folded miss":     {stable("Other_Get"), "Nope_Get", 2, apiref.OutcomeNotFound},
		"case ambiguity":  {stable("things_get", "THINGS_GET"), "Things_Get", 2, apiref.OutcomeAmbiguous},
		"final file read": {stable("Things_Get"), "Things_Get", 0, apiref.OutcomeFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if res := lookup(t, specFixture(tc.file), tc.op, ""); res.Outcome != tc.original {
				t.Fatalf("uncancelled = %+v, want %s", res, tc.original)
			}
			f := specFixture(tc.file)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			f.onSummary = func() {
				if calls.Add(1) == tc.atCall {
					cancel()
				}
			}
			var store specSource = f
			if tc.atCall == 0 {
				store = &cancelOnRender{fakeSpecs: f, cancel: cancel}
			}
			res := NewDocs(store, "e", func() Catalog { return nil }).Reference(ctx,
				apiref.Query{Service: "Microsoft.Test", Operation: tc.op})
			if res.Outcome != apiref.OutcomeUnavailable ||
				!strings.HasPrefix(res.Reason, "the lookup was interrupted") {
				t.Fatalf("cancelled = %+v, want unavailable", res)
			}
		})
	}
}

// TestRequestKey pins what makes two matches one request: everything but the api-version.
func TestRequestKey(t *testing.T) {
	t.Parallel()
	base := func() *apiref.Reference {
		return &apiref.Reference{
			Method: "GET", PathTemplate: "/p", BodyEncoding: apiref.BodyNone,
			FixedQuery:   []apiref.Param{{Key: apiVersionParam, Value: "2024-01-01"}},
			FixedHeaders: []apiref.Param{{Key: "x-ms-mode", Value: "A"}},
			Inputs: []apiref.Input{{
				Name: "n", WireName: "n", Location: apiref.LocationQuery, Required: true,
				Type: "string",
			}},
		}
	}
	other := base()
	other.FixedQuery[0].Value = "2023-01-01"
	if requestKey(base()) != requestKey(other) {
		t.Error("the api-version split two otherwise identical requests")
	}
	for name, change := range map[string]func(*apiref.Reference){
		"fixed header": func(r *apiref.Reference) { r.FixedHeaders[0].Value = "B" },
		"input type":   func(r *apiref.Reference) { r.Inputs[0].Type = "integer" },
		"body":         func(r *apiref.Reference) { r.BodyEncoding = apiref.BodyJSON },
		"fixed query": func(r *apiref.Reference) {
			r.FixedQuery = append(r.FixedQuery, apiref.Param{Key: "k", Value: "v"})
		},
		"optional": func(r *apiref.Reference) { r.Inputs[0].Required = false },
	} {
		r := base()
		change(r)
		if requestKey(r) == requestKey(base()) {
			t.Errorf("%s: two different requests share a key", name)
		}
	}
}

func TestDocsReference_NearestFromSearchedFiles(t *testing.T) {
	t.Parallel()
	f := specFixture(fixtureFile{
		"A", kindStable, "2024-01-01", "a.json",
		specOps("2024-01-01", "VirtualMachines_List", "VirtualMachines_Get", "Disks_List"),
	})
	res := lookup(t, f, "VirtualMachine_List", "")
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, `"VirtualMachines_List"`) {
		t.Fatalf("nearest = %+v", res)
	}
	if res.Choices != nil {
		t.Errorf("not_found carries choices %v", res.Choices)
	}

	// An id too long to list whole is left out, never cut: a cut id is no operation to retry with.
	long := strings.Repeat("Long", 30) + "_List"
	f = specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", long)})
	res = lookup(t, f, strings.Repeat("Long", 30)+"_Lisst", "")
	if res.Outcome != apiref.OutcomeNotFound || strings.Contains(res.Reason, "nearest operation ids") {
		t.Fatalf("a long nearest id = %+v, want it left out", res)
	}
}

// TestDocsReference_PassOrder pins what each pass reads: pass 2 walks a group's older stable dirs until one defines
// the operation, and pass 3 never runs once a stable dir defined it.
func TestDocsReference_PassOrder(t *testing.T) {
	t.Parallel()
	other := strings.Replace(specOps("2025-01-01-preview", "Things_Get"), "things/Things_Get", "other/Things_Get", 1)
	f := specFixture(
		fixtureFile{"Test", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		fixtureFile{"Test", kindStable, "2023-01-01", "a.json", specOps("2023-01-01", "Old_Get")},
		fixtureFile{"Test", kindStable, "2022-01-01", "a.json", specOps("2022-01-01", "Older_Get")},
		fixtureFile{"Test", kindPreview, "2025-01-01-preview", "a.json", other},
	)
	res := lookup(t, f, "Older_Get", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.APIVersion != "2022-01-01" {
		t.Fatalf("pass 2 past a dir without the operation = %+v", res)
	}
	preview := fixtureFile{"Test", kindPreview, "2025-01-01-preview", "a.json", ""}.path()
	if n := f.summaryCount(preview); n != 0 {
		t.Errorf("pass 3 read the preview dir %d times after a stable dir defined the operation", n)
	}
	res = lookup(t, f, "Things_Get", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.APIVersion != "2024-01-01" {
		t.Fatalf("a stable match with a differing preview request = %+v", res)
	}
}

// TestDocsReference_ChoicesCap pins that the choices kept are the first five in group id order, before
// apiref.Choices sorts them: group "test/E-x" sorts after "test/E" by group id but before it as a selector.
func TestDocsReference_ChoicesCap(t *testing.T) {
	t.Parallel()
	var files []fixtureFile
	for _, svc := range []string{"A", "B", "C", "D", "E", "E-x"} {
		files = append(files, fixtureFile{
			svc, kindPreview, "2024-01-01-preview", "a.json",
			specOps("2024-01-01-preview", "New_Get"),
		})
	}
	res := lookup(t, specFixture(files...), "New_Get", "")
	want := "[test/A@preview/2024-01-01-preview test/B@preview/2024-01-01-preview " +
		"test/C@preview/2024-01-01-preview test/D@preview/2024-01-01-preview test/E@preview/2024-01-01-preview]"
	if res.Outcome != apiref.OutcomeAmbiguous || fmt.Sprint(res.Choices) != want {
		t.Fatalf("choices = %+v, want %s", res, want)
	}
}

// TestDocsReference_ManyCandidateFilesAnswerChoices pins that an id defined in more groups than one lookup has file
// slots for answers ambiguous with selectors, not unavailable with a load failure: the candidate files count toward
// the per-lookup file bound, and running out of it is the lookup's limit, not a broken spec file.
func TestDocsReference_ManyCandidateFilesAnswerChoices(t *testing.T) {
	t.Parallel()
	var files []fixtureFile
	for i := range maxRefFiles + 1 {
		files = append(files, fixtureFile{
			fmt.Sprintf("G%02d", i), kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Operations_List"),
		})
	}
	res := lookup(t, specFixture(files...), "Operations_List", "")
	if res.Outcome != apiref.OutcomeAmbiguous || len(res.Choices) != apiref.MaxChoices ||
		!strings.Contains(res.Reason, `several operations named "Operations_List" span more spec files`) ||
		!strings.Contains(res.Reason, "pass model with one of the choices") {
		t.Fatalf("%d groups = %+v, want ambiguous with %d choices", len(files), res, apiref.MaxChoices)
	}
	if got := fmt.Sprint(res.Choices); got != "[test/G00@stable/2024-01-01 test/G01@stable/2024-01-01 "+
		"test/G02@stable/2024-01-01 test/G03@stable/2024-01-01 test/G04@stable/2024-01-01]" {
		t.Errorf("choices = %s", got)
	}
}

// TestDocsReference_OperationEcho pins that the echoed operation is quoted and bounded before the text after it,
// so a long, escape-heavy operation cannot push the namespace or the guidance out of the reason: outside the
// operation grammar it is refused with the grammar, and at the grammar's longest it is searched for.
func TestDocsReference_OperationEcho(t *testing.T) {
	t.Parallel()
	f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")})
	for _, op := range []string{strings.Repeat(`"\`, 600), strings.Repeat("x", 1200)} {
		res := lookup(t, f, op, "")
		if res.Outcome != apiref.OutcomeNotFound || utf8.RuneCountInString(res.Reason) > apiref.MaxReason {
			t.Fatalf("%.20q = %s %q", op, res.Outcome, res.Reason)
		}
		if !strings.HasPrefix(res.Reason, "operation "+strconv.Quote(op)[:20]) {
			t.Errorf("%.20q: the operation was not quoted: %q", op, res.Reason)
		}
		if !strings.HasSuffix(res.Reason, " is not a Swagger operationId"+operationGrammar) {
			t.Errorf("%.20q: the text after the echo did not survive: %q", op, res.Reason)
		}
	}
	op := strings.Repeat("x", 200)
	res := lookup(t, f, op, "")
	if res.Outcome != apiref.OutcomeNotFound || utf8.RuneCountInString(res.Reason) > apiref.MaxReason ||
		!strings.HasPrefix(res.Reason, "no operation "+strconv.Quote(op)[:20]) {
		t.Fatalf("a 200-byte operation = %s %q", res.Outcome, res.Reason)
	}
	if !strings.Contains(res.Reason, " in Microsoft.Test (1 version dirs searched in groups test/A)") ||
		!strings.HasSuffix(res.Reason, olderGuidance) {
		t.Errorf("a 200-byte operation: the text after the echo did not survive: %q", res.Reason)
	}
}

// TestDocsReference_OperationGrammar pins the operation grammar's edges: 200 bytes is searched, 201 and a character
// outside the grammar are refused before any store call.
func TestDocsReference_OperationGrammar(t *testing.T) {
	t.Parallel()
	for op, searched := range map[string]bool{
		"A" + strings.Repeat("b", 199): true,
		"A" + strings.Repeat("b", 200): false,
		"Things Get":                   false,
		"Things/Get":                   false,
		"_Things":                      false,
		"":                             false,
		"0.Things-Get_x":               true,
	} {
		f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")})
		res := lookup(t, f, op, "")
		refused := strings.HasSuffix(res.Reason, operationGrammar)
		if op == "_Things" && !strings.Contains(res.Reason, "starts with a letter or digit") {
			t.Errorf("_Things: the guidance %q does not state the first-character rule it fails", res.Reason)
		}
		if res.Outcome != apiref.OutcomeNotFound || refused == searched || (f.indexCount() > 0) != searched {
			t.Errorf("%.20q: %s %q after %d index loads; want searched %v", op, res.Outcome, res.Reason,
				f.indexCount(), searched)
		}
		if !searched && (len(f.calls) != 0 || len(f.summaries) != 0) {
			t.Errorf("%.20q: a refused operation read %d files and %d summaries", op, len(f.calls), len(f.summaries))
		}
	}
}

// TestDocsReference_StoreErrorsUseTheLookupContext pins that a store error is judged by the lookup's own context:
// a store error wrapping another caller's cancellation, with the lookup still live, answers the store's text.
func TestDocsReference_StoreErrorsUseTheLookupContext(t *testing.T) {
	t.Parallel()
	shared := fmt.Errorf("the shared index load failed: %w", context.Canceled)
	f := specFixture()
	f.indexErr = shared
	res := lookup(t, f, "X", "")
	if res.Outcome != apiref.OutcomeUnavailable ||
		res.Reason != "the Azure REST API specs index could not be loaded: "+shared.Error() {
		t.Fatalf("index error wrapping a cancel with a live lookup = %+v", res)
	}

	files := []fixtureFile{{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")}}
	f = specFixture(files...)
	f.summaryErr[files[0].path()] = fmt.Errorf("download: %w", context.Canceled)
	res = lookup(t, f, "Things_Get", "")
	if res.Outcome != apiref.OutcomeUnavailable ||
		!strings.HasPrefix(res.Reason, "a spec file could not be loaded: download: context canceled") {
		t.Fatalf("summary error wrapping a cancel with a live lookup = %+v", res)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f = specFixture()
	f.indexErr = errors.New("listing failed: 503")
	res = NewDocs(f, "e", func() Catalog { return nil }).Reference(ctx,
		apiref.Query{Service: "Microsoft.Test", Operation: "X"})
	if res.Outcome != apiref.OutcomeUnavailable || res.Reason != "the lookup was interrupted" {
		t.Fatalf("index error with the lookup cancelled = %+v", res)
	}
}

// TestDocsReference_FileSelectorOutsideTheIndex pins that a selector's file is matched against the index, never
// built from query text: a file the index does not list is read from no store call.
func TestDocsReference_FileSelectorOutsideTheIndex(t *testing.T) {
	t.Parallel()
	f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")})
	res := lookup(t, f, "Things_Get", "test/A@stable/2024-01-01/missing.json")
	if res.Outcome != apiref.OutcomeNotFound ||
		!strings.HasPrefix(res.Reason, `no "test/A@stable/2024-01-01/missing.json" in Microsoft.Test;`) {
		t.Fatalf("a file outside the index = %+v", res)
	}
	f.mu.Lock()
	n := len(f.summaries)
	f.mu.Unlock()
	if n != 0 || len(f.calls) != 0 {
		t.Errorf("a file outside the index read %d summaries and %d files", n, len(f.calls))
	}
}

// swappedFile serves summaries from the fixture body and File from body, so the render reads another file.
type swappedFile struct {
	*fakeSpecs

	body []byte
}

func (s *swappedFile) File(context.Context, string, IndexFile) ([]byte, error) { return s.body, nil }

// TestDocsReference_RenderStops pins the render's own stops: a model search's load error, the budget charged for
// the file the render reads, and a file that does not decode.
func TestDocsReference_RenderStops(t *testing.T) {
	t.Parallel()
	files := []fixtureFile{{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")}}
	f := specFixture(files...)
	f.summaryErr[files[0].path()] = errors.New("summary failed")
	if res := lookup(t, f, "Things_Get", "2024-01-01"); res.Outcome != apiref.OutcomeUnavailable ||
		!strings.Contains(res.Reason, "summary failed") {
		t.Fatalf("model search load error = %+v", res)
	}

	d := NewDocs(specFixture(files...), "e", func() Catalog { return nil })
	d.budget = int64(len(files[0].body) + 1)
	res := d.Reference(context.Background(), apiref.Query{Service: "Microsoft.Test", Operation: "Things_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || !strings.Contains(res.Reason, "budget") {
		t.Fatalf("render over the budget = %+v", res)
	}

	sw := &swappedFile{fakeSpecs: specFixture(files...), body: []byte("{")}
	res = NewDocs(sw, "e", func() Catalog { return nil }).Reference(context.Background(),
		apiref.Query{Service: "Microsoft.Test", Operation: "Things_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || !strings.HasPrefix(res.Reason, "a spec file could not be loaded: ") {
		t.Fatalf("render decode error = %+v", res)
	}
}

// TestDocsReference_Bounds pins the lookup's deadline and budget as NewDocs sets them.
func TestDocsReference_Bounds(t *testing.T) {
	t.Parallel()
	f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")})
	var left time.Duration
	f.onIndex = func(ctx context.Context) {
		dl, _ := ctx.Deadline()
		left = time.Until(dl)
	}
	d := NewDocs(f, "e", func() Catalog { return nil })
	if d.budget != 160<<20 {
		t.Errorf("budget = %d, want 160 MiB", d.budget)
	}
	d.Reference(context.Background(), apiref.Query{Service: "Microsoft.Test", Operation: "Things_Get"})
	if left < 119*time.Second || left > 121*time.Second {
		t.Errorf("the lookup's deadline was %v away, want 120s", left)
	}
}

// blockingSpecs holds every Summary until release closes and records the peak number held at once.
type blockingSpecs struct {
	*fakeSpecs

	release chan struct{}
	active  int
	peak    int
}

func (b *blockingSpecs) Summary(ctx context.Context, sha string, file IndexFile, budget *Budget) (*FileSummary, error) {
	b.mu.Lock()
	b.active++
	b.peak = max(b.peak, b.active)
	b.mu.Unlock()
	<-b.release
	b.mu.Lock()
	b.active--
	b.mu.Unlock()

	return b.fakeSpecs.Summary(ctx, sha, file, budget)
}

// TestDocsReference_DownloadLimit pins that a dir's summaries are read at most maxLookupDownloads at a time. Inside
// a synctest bubble, Wait returns only once every lookup goroutine is durably blocked, either in a held Summary or
// in errgroup waiting for a slot, so the count it sees is the most the limit lets in.
func TestDocsReference_DownloadLimit(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var files []fixtureFile
		for i := range 12 {
			files = append(files, fixtureFile{
				"A", kindStable, "2024-01-01", fmt.Sprintf("f%02d.json", i),
				specOps("2024-01-01", fmt.Sprintf("Op%02d_Get", i)),
			})
		}
		b := &blockingSpecs{fakeSpecs: specFixture(files...), release: make(chan struct{})}
		done := make(chan apiref.Result)
		go func() {
			done <- NewDocs(b, "e", func() Catalog { return nil }).Reference(context.Background(),
				apiref.Query{Service: "Microsoft.Test", Operation: "Op00_Get"})
		}()
		synctest.Wait()
		b.mu.Lock()
		held := b.active
		b.mu.Unlock()
		close(b.release)
		res := <-done
		if held != 8 || b.peak != 8 || res.Outcome != apiref.OutcomeFound {
			t.Fatalf("held %d, peak %d, want 8 and 8; result %+v", held, b.peak, res)
		}
	})
}

// TestDocsReference_NearestAndGroups pins the not_found reason's lists: at most five nearest ids in edit-distance
// order, and at most five searched groups in sorted order, then how many more.
func TestDocsReference_NearestAndGroups(t *testing.T) {
	t.Parallel()
	f := specFixture(fixtureFile{
		"A", kindStable, "2024-01-01", "a.json",
		specOps("2024-01-01", "Abcdef", "Zabcde", "Zzabcd", "Zzzabc", "Zzzzab", "Zzzzza"),
	})
	res := lookup(t, f, "Zzzzzz", "")
	want := `; nearest operation ids: "Zzzzza", "Zzzzab", "Zzzabc", "Zzabcd", "Zabcde";`
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, want) {
		t.Fatalf("nearest = %+v, want %s", res, want)
	}

	var files []fixtureFile
	for _, svc := range []string{"G", "F", "E", "D", "C", "B", "A"} {
		files = append(files, fixtureFile{svc, kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "X_Get")})
	}
	res = lookup(t, specFixture(files...), "Nope", "")
	want = "(7 version dirs searched in groups test/A, test/B, test/C, test/D, test/E and 2 more)"
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, want) {
		t.Fatalf("groups = %+v, want %s", res, want)
	}
}

// TestDocsReference_NearestScoresOnlyListableIDs pins that an id the reason could not list, too long or outside the
// operation grammar, is dropped before scoring: five long ids nearer the operation than a short one never crowd it
// out of the list.
func TestDocsReference_NearestScoresOnlyListableIDs(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("L", 120)
	ids := []string{"Short_Get"}
	for _, c := range "ABCDE" {
		ids = append(ids, long+"_"+string(c))
	}
	body := specOps("2024-01-01", ids...)
	// An id with a space is outside the grammar; it is as near as the long ones.
	body = strings.Replace(body, `"operationId":"`+long+`_E"`, `"operationId":"`+long+` E"`, 1)
	f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", body})
	res := lookup(t, f, long+"_X", "")
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, `; nearest operation ids: "Short_Get";`) {
		t.Fatalf("nearest = %+v, want only the short id listed", res)
	}
}

// TestDocsReference_NearestEchoBoundary pins the listing's edge: an id whose quoted form is exactly maxNearestEcho
// bytes is listed, one byte longer is not.
func TestDocsReference_NearestEchoBoundary(t *testing.T) {
	t.Parallel()
	fits := strings.Repeat("a", maxNearestEcho-2)
	over := strings.Repeat("b", maxNearestEcho-1)
	f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", fits, over)})
	res := lookup(t, f, "Nope", "")
	if res.Outcome != apiref.OutcomeNotFound || !strings.Contains(res.Reason, `; nearest operation ids: "`+fits+`";`) ||
		strings.Contains(res.Reason, over) {
		t.Fatalf("nearest = %+v, want only the id of %d bytes quoted", res, maxNearestEcho-2)
	}
}

// TestDocsReference_NoNearestAfterTheLookupEnds pins that a stopped lookup scores nothing: the context ends while the
// first dir's summary is read, after which the search stops with ids already seen and lists none of them.
func TestDocsReference_NoNearestAfterTheLookupEnds(t *testing.T) {
	t.Parallel()
	f := specFixture(
		fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		fixtureFile{"A", kindStable, "2023-01-01", "a.json", specOps("2023-01-01", "Other_Get")},
	)
	ctx, cancel := context.WithCancel(context.Background())
	f.onSummary = cancel
	res := NewDocs(f, "e", func() Catalog { return nil }).Reference(ctx,
		apiref.Query{Service: "Microsoft.Test", Operation: "Thingz_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || !strings.HasPrefix(res.Reason, "the lookup was interrupted") ||
		strings.Contains(res.Reason, "nearest") {
		t.Fatalf("a stopped lookup = %+v, want no nearest ids", res)
	}
}

// TestDocsReference_RepeatedParentsAnswerAGap pins what a lookup makes of the decode bound: an operation with 200 body
// parameters whose schema names one large definition a thousand times reaches the bound, since every body merges
// that definition again, and the bodies past it are gaps while the rest of the reference is rendered.
func TestDocsReference_RepeatedParentsAnswerAGap(t *testing.T) {
	t.Parallel()
	params := []string{pSub, pVersion}
	for i := range 200 {
		params = append(params, fmt.Sprintf(
			`{"name":"body%d","in":"body","required":true,"schema":{"$ref":"#/definitions/VM"}}`, i))
	}
	spec := `{"info":{"version":"2024-01-01"},"paths":{` +
		`"/subscriptions/{subscriptionId}/providers/Microsoft.Test/things/x":{"put":{"operationId":"Things_Put",` +
		`"parameters":[` + strings.Join(params, ",") + `]}}},"definitions":` + repeatedParents(1000, 64<<10) + `}`
	res := lookup(t, specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", spec}), "Things_Put", "")
	if res.Outcome != apiref.OutcomeIncomplete || !slices.Contains(res.Reference.Gaps, refBodyGap) ||
		res.Reference.Operation != "Things_Put" {
		t.Fatalf("repeated parents = %+v, want incomplete with the body gap", res)
	}
}

// TestDocsReference_RenderChargesTheBudget pins the budget charge for the file the render reads, with a file that
// refs nothing, so no other read can trip the budget: the summary takes all but one byte, and the render's read of
// the same file is refused.
func TestDocsReference_RenderChargesTheBudget(t *testing.T) {
	t.Parallel()
	inline := `{"info":{"version":"2024-01-01"},"paths":{` +
		`"/subscriptions/{subscriptionId}/providers/Microsoft.Test/things":{"get":{"operationId":"Things_List",` +
		`"parameters":[{"name":"subscriptionId","in":"path","required":true,"type":"string"},` +
		`{"name":"api-version","in":"query","required":true,"type":"string"}]}}}}`
	files := []fixtureFile{{"A", kindStable, "2024-01-01", "a.json", inline}}
	if res := lookup(t, specFixture(files...), "Things_List", ""); res.Outcome != apiref.OutcomeFound {
		t.Fatalf("within the budget = %+v", res)
	}
	d := NewDocs(specFixture(files...), "e", func() Catalog { return nil })
	d.budget = int64(len(inline) + 1)
	res := d.Reference(context.Background(), apiref.Query{Service: "Microsoft.Test", Operation: "Things_List"})
	if res.Outcome != apiref.OutcomeUnavailable ||
		!strings.HasPrefix(res.Reason, "the search stopped at the per-lookup "+
			"budget") {
		t.Fatalf("render over the budget = %+v", res)
	}
}

// TestDocsReference_PassOneReadsOnlyTheNewestDir pins pass 1's bound: a group whose newest stable dir lacks the
// operation is not searched further while another group's newest dir defines it, so the older dir's differing
// request never joins the candidates.
func TestDocsReference_PassOneReadsOnlyTheNewestDir(t *testing.T) {
	t.Parallel()
	other := strings.Replace(specOps("2023-01-01", "Things_Get"), "things/Things_Get", "other/Things_Get", 1)
	f := specFixture(
		fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")},
		fixtureFile{"B", kindStable, "2024-02-01", "b.json", specOps("2024-02-01", "Else_Get")},
		fixtureFile{"B", kindStable, "2023-01-01", "b.json", other},
	)
	res := lookup(t, f, "Things_Get", "")
	if res.Outcome != apiref.OutcomeFound || res.Reference.Model != "test/A@stable/2024-01-01" {
		t.Fatalf("pass 1 = %+v, want found in test/A@stable/2024-01-01", res)
	}
	older := fixtureFile{"B", kindStable, "2023-01-01", "b.json", ""}.path()
	if n := f.summaryCount(older); n != 0 {
		t.Errorf("pass 1 read group B's older dir %d times", n)
	}
}

// countingNearest is a Docs.nearest that counts its calls and the ids it scored, running after when set.
type countingNearest struct {
	calls, scored atomic.Int32
	after         func()
}

func (c *countingNearest) nearest(ids []string, target string, n int) []string {
	c.calls.Add(1)
	c.scored.Add(int32(len(ids)))
	if c.after != nil {
		c.after()
	}

	return apiref.Nearest(ids, target, n)
}

// TestDocsReference_NoScoringAfterTheFinalSummary pins that the not_found reason scores nothing once the context is
// done: the context ends during the folded pass's final summary read, which leaves the search to conclude not_found,
// and no id is scored on the way to the unavailable answer.
func TestDocsReference_NoScoringAfterTheFinalSummary(t *testing.T) {
	t.Parallel()
	f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Other_Get")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	f.onSummary = func() {
		if calls.Add(1) == 2 {
			cancel()
		}
	}
	d := NewDocs(f, "e", func() Catalog { return nil })
	scorer := &countingNearest{}
	d.nearest = scorer.nearest
	res := d.Reference(ctx, apiref.Query{Service: "Microsoft.Test", Operation: "Othr_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || calls.Load() != 2 || scorer.calls.Load() != 0 {
		t.Fatalf("cancelled at the final summary = %+v after %d summaries and %d scorings; want unavailable and "+
			"no scoring", res, calls.Load(), scorer.calls.Load())
	}
	scorer = &countingNearest{}
	d.nearest = scorer.nearest
	f.onSummary = nil
	if res = d.Reference(context.Background(), apiref.Query{Service: "Microsoft.Test", Operation: "Othr_Get"}); res.
		Outcome != apiref.OutcomeNotFound || scorer.scored.Load() != 1 {
		t.Fatalf("uncancelled = %+v after %d ids scored, want not_found scoring the one id", res, scorer.scored.Load())
	}
}

// nearestSearch is a search over no index that has seen n ids, Op_0 to Op_<n-1>, looking for "Op_x".
func nearestSearch(d *Docs, n int) *search {
	s := newSearch(d, &Index{}, &IndexNamespace{}, apiref.Query{Operation: "Op_x"})
	for i := range n {
		s.ids[fmt.Sprintf("Op_%d", i)] = true
	}

	return s
}

// TestSearchNearest_Batches pins the batched scoring: 1,000 seen ids are scored nearestBatch at a time with the same
// list as one scoring of all of them, and a context that ends after the first batch stops the rest and lists nothing.
func TestSearchNearest_Batches(t *testing.T) {
	t.Parallel()
	d := NewDocs(specFixture(), "e", func() Catalog { return nil })
	scorer := &countingNearest{}
	d.nearest = scorer.nearest
	s := nearestSearch(d, 1000)
	var quoted []string
	for _, id := range apiref.Nearest(slices.Collect(maps.Keys(s.ids)), "Op_x", maxNearest) {
		quoted = append(quoted, strconv.Quote(id))
	}
	want := "; nearest operation ids: " + strings.Join(quoted, ", ")
	if got := s.nearest(context.Background()); got != want || scorer.calls.Load() != 4 {
		t.Fatalf("nearest = %q after %d scorings, want %q after 4", got, scorer.calls.Load(), want)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scorer = &countingNearest{after: cancel}
	d.nearest = scorer.nearest
	if got := nearestSearch(d, 1000).nearest(ctx); got != "" || scorer.calls.Load() != 1 ||
		scorer.scored.Load() != nearestBatch {
		t.Fatalf("cancelled in the first batch: %q after %d scorings of %d ids; want nothing after one of %d", got,
			scorer.calls.Load(), scorer.scored.Load(), nearestBatch)
	}
}

// TestDocsReference_DoneContextBeforeTheNamespace pins the check after a warm index: a done lookup whose namespace
// the index lacks answers unavailable, not not_found, though the index came back without looking at the context.
func TestDocsReference_DoneContextBeforeTheNamespace(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := specFixture(fixtureFile{"A", kindStable, "2024-01-01", "a.json", specOps("2024-01-01", "Things_Get")})
	res := NewDocs(f, "e", func() Catalog { return nil }).Reference(ctx,
		apiref.Query{Service: "Microsoft.Missing", Operation: "Things_Get"})
	if res.Outcome != apiref.OutcomeUnavailable || res.Reason != "the lookup was interrupted" || f.indexCount() != 1 {
		t.Fatalf("done lookup, missing namespace = %+v after %d index loads; want unavailable", res, f.indexCount())
	}
}

// TestDocsReference_SummaryErrorStopsScheduling pins that a dir's summaries stop at the first error. The first file
// fails at once while every other file read holds its slot. Inside a synctest bubble, Wait returns once the lookup is
// durably blocked: with the stop, the loop has scheduled no file past the one that took the failed file's slot and
// waits for the group; without it, the loop waits for a slot to schedule the next file, which it reads once the held
// reads are released. How many files before that bound start depends on when the failure lands, so only the bound is
// pinned.
func TestDocsReference_SummaryErrorStopsScheduling(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		files := make([]fixtureFile, 3*maxLookupDownloads)
		for i := range files {
			files[i] = fixtureFile{
				"A", kindStable, "2024-01-01", fmt.Sprintf("f%02d.json", i),
				specOps("2024-01-01", fmt.Sprintf("Op%02d_Get", i)),
			}
		}
		f := specFixture(files...)
		f.summaryErr[files[0].path()] = errors.New("summary failed")
		release := make(chan struct{})
		f.onSummary = func() { <-release }
		done := make(chan apiref.Result)
		go func() { done <- lookup(t, f, "Op00_Get", "") }()
		synctest.Wait()
		close(release)
		res := <-done
		const reason = "a spec file could not be loaded: summary failed; 0 version dirs searched; pass model with " +
			"an api-version dir name to search one version"
		if res.Outcome != apiref.OutcomeUnavailable || res.Reason != reason || res.Reference != nil {
			t.Fatalf("result = %+v", res)
		}
		for i, file := range files {
			got := f.summaryCount(file.path())
			switch {
			case i == 0 && got != 1:
				t.Errorf("the failing file read %d times, want 1", got)
			case i > maxLookupDownloads && got != 0:
				t.Errorf("file %d read %d times after the first error, want 0", i, got)
			}
		}
	})
}
