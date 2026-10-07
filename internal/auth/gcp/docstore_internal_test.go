package gcp

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/cache"
)

// testDirectory lists the fixture documents under mem:// URLs, plus entries whose documents fail to load or must
// never be fetched.
const testDirectory = `{"items":[
{"name":"compute","version":"v1","discoveryRestUrl":"mem://compute.v1"},
{"name":"compute","version":"stable","discoveryRestUrl":"mem://compute.stable"},
{"name":"compute","version":"beta","discoveryRestUrl":"mem://missing"},
{"name":"cloudresourcemanager","version":"v3","discoveryRestUrl":"mem://cloudresourcemanager.v3"},
{"name":"cloudresourcemanager","version":"v1","discoveryRestUrl":"mem://cloudresourcemanager.v1"},
{"name":"cloudresourcemanager","version":"v2beta1","discoveryRestUrl":"mem://never"},
{"name":"storage","version":"v1","discoveryRestUrl":"mem://storage.v1"},
{"name":"aiplatform","version":"v1","discoveryRestUrl":"mem://aiplatform.v1"},
{"name":"aiplatform","version":"v1beta1","discoveryRestUrl":"mem://never"},
{"name":"synth","version":"v1","discoveryRestUrl":"mem://synth.v1"},
{"name":"labs","version":"v1alpha","discoveryRestUrl":"mem://never"},
{"name":"labs","version":"v2beta","discoveryRestUrl":"mem://never"},
{"name":"broken","version":"v1","discoveryRestUrl":"mem://missing"},
{"name":"unsafe","version":"..","discoveryRestUrl":"mem://never"},
{"name":"Dup","version":"v1","discoveryRestUrl":"mem://never"},
{"name":"dup","version":"v1","discoveryRestUrl":"mem://never"}
]}`

var errNoFixture = errors.New("no fixture")

// memFetch serves testDirectory and the fixtures, records every URL, and fails mem://missing and mem://never.
type memFetch struct {
	t    *testing.T
	mu   sync.Mutex
	urls []string
}

func (m *memFetch) fetch(_ context.Context, url string) ([]byte, error) {
	m.mu.Lock()
	m.urls = append(m.urls, url)
	m.mu.Unlock()
	switch url {
	case "mem://directory":
		return []byte(testDirectory), nil
	case "mem://missing":
		return nil, errNoFixture
	case "mem://never":
		m.t.Errorf("fetched %s, which no lookup may load", url)
		return nil, errNoFixture
	}
	return fixture(m.t, strings.TrimPrefix(url, "mem://")), nil
}

func (m *memFetch) fetched() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.urls)
}

func newTestDocs(t *testing.T, dir string, clock func() time.Time) (*Docs, *memFetch) {
	t.Helper()
	m := &memFetch{t: t}
	cfg := cache.Config{Dir: dir, TTL: time.Hour, Clock: clock}
	return NewDocs(cfg, "mem://directory", m.fetch), m
}

func lookup(t *testing.T, d *Docs, op, model string) apiref.Result {
	t.Helper()
	return d.Reference(t.Context(), apiref.Query{Connector: "gcp", Model: model, Operation: op})
}

func TestDocs_VersionSelection(t *testing.T) {
	t.Parallel()
	d, _ := newTestDocs(t, t.TempDir(), time.Now)
	for _, tc := range []struct {
		op, model, version string
	}{
		{"compute.instances.list", "", "v1"},
		{"COMPUTE.Instances.List", "", "v1"},
		{"compute.instances.get", "stable", "stable"},
		{"cloudresourcemanager.projects.get", "", "v1"},
		{"cloudresourcemanager.projects.search", "", "v3"},
		{"cloudresourcemanager.projects.list", "v3", "v3"},
	} {
		res := lookup(t, d, tc.op, tc.model)
		if res.Reference == nil || res.Reference.Model != tc.version || res.Reference.APIVersion != tc.version {
			t.Errorf("%s model %q = %+v, want version %s", tc.op, tc.model, res, tc.version)
			continue
		}
		if !strings.EqualFold(res.Reference.Operation, tc.op) {
			t.Errorf("%s resolved to %s", tc.op, res.Reference.Operation)
		}
	}
}

func TestDocs_Ambiguous(t *testing.T) {
	t.Parallel()
	d, _ := newTestDocs(t, t.TempDir(), time.Now)
	res := lookup(t, d, "cloudresourcemanager.projects.list", "")
	if res.Outcome != apiref.OutcomeAmbiguous || !slices.Equal(res.Choices, []string{"v1", "v3"}) {
		t.Errorf("projects.list = %+v, want ambiguous between v1 and v3", res)
	}
	res = lookup(t, d, "DUP.things.get", "")
	if res.Outcome != apiref.OutcomeAmbiguous || !slices.Equal(res.Choices, []string{"Dup", "dup"}) {
		t.Errorf("DUP = %+v, want ambiguous between Dup and dup", res)
	}
}

func TestDocs_NotFound(t *testing.T) {
	t.Parallel()
	d, _ := newTestDocs(t, t.TempDir(), time.Now)
	for _, tc := range []struct{ op, model, reason string }{
		{"compute.instances.nope", "", `no operation "compute.instances.nope" in the default-eligible versions ` +
			`searched (v1); other versions to try with model: beta, stable; ` + docNameFormat},
		{"labs.things.get", "", `no operation "labs.things.get" in the default-eligible versions searched (none); ` +
			`other versions to try with model: v1alpha, v2beta; ` + docNameFormat},
		{"storage.objects.nope", "", `no operation "storage.objects.nope" in the default-eligible versions ` +
			`searched (v1); ` + docNameFormat},
		{"compute.instances.insert", "stable", `no operation "compute.instances.insert" in compute stable; ` +
			docNameFormat},
		{"compute.instances.get", "v9", `API compute has no version "v9"; its versions are beta, stable, v1; ` +
			docNameFormat},
		{"nope.things.get", "", `API "nope" is not in the Google API Discovery directory; ` + docNameFormat},
		{"projects/compute.instances.list", "", `API "projects/compute" is not in the Google API Discovery ` +
			`directory; GCP operation names carry no prefix: did you mean "compute.instances.list"?`},
		{"a/b/nope.x.y", "", `API "a/b/nope" is not in the Google API Discovery directory; ` + docNameFormat},
	} {
		res := lookup(t, d, tc.op, tc.model)
		if res.Outcome != apiref.OutcomeNotFound || res.Reason != tc.reason {
			t.Errorf("%s model %q = %s %q\nwant reason %q", tc.op, tc.model, res.Outcome, res.Reason, tc.reason)
		}
	}
}

func TestDocs_NotFoundEchoIsBounded(t *testing.T) {
	t.Parallel()
	d, _ := newTestDocs(t, t.TempDir(), time.Now)
	res := lookup(t, d, "compute."+strings.Repeat("x", 1000), "")
	if !strings.HasSuffix(res.Reason, docNameFormat) || len([]rune(res.Reason)) > apiref.MaxReason {
		t.Errorf("reason = %q, want a bounded echo followed by the name format", res.Reason)
	}
}

func TestDocs_Unavailable(t *testing.T) {
	t.Parallel()
	d, _ := newTestDocs(t, t.TempDir(), time.Now)
	for _, tc := range []struct{ op, model, reason string }{
		{"broken.things.get", "", "the Discovery document broken v1 could not be loaded"},
		{"compute.instances.get", "beta", "the Discovery document compute beta could not be loaded"},
		{"unsafe.things.get", "..", "the Discovery document unsafe .. could not be loaded"},
	} {
		if res := lookup(t, d, tc.op, tc.model); res.Outcome != apiref.OutcomeUnavailable || res.Reason != tc.reason {
			t.Errorf("%s model %q = %+v, want unavailable %q", tc.op, tc.model, res, tc.reason)
		}
	}
	m := &memFetch{t: t}
	failing := NewDocs(cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now}, "mem://missing", m.fetch)
	if res := lookup(t, failing, "compute.instances.get", ""); res.Outcome != apiref.OutcomeUnavailable {
		t.Errorf("no directory = %+v, want unavailable", res)
	}
}

func TestDocs_CachesOnDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	d, m := newTestDocs(t, dir, func() time.Time { return now })
	if res := lookup(t, d, "compute.instances.get", ""); res.Reference == nil {
		t.Fatalf("lookup = %+v", res)
	}
	_ = lookup(t, d, "compute.instances.list", "")
	if got := m.fetched(); !slices.Equal(got, []string{"mem://directory", "mem://compute.v1"}) {
		t.Errorf("fetched %q, want the directory and compute v1 once each", got)
	}
	for _, f := range []string{"directory.json", "directory.meta", "compute.v1.json", "compute.v1.meta"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("cache file %s: %v", f, err)
		}
	}
	// A day later both copies are past the TTL, so a second store tries to download the directory and the document
	// again; every download fails, and the stale copies on disk answer.
	var mu sync.Mutex
	var tried []string
	failing := func(_ context.Context, url string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		tried = append(tried, url)
		return nil, errNoFixture
	}
	later := cache.Config{Dir: dir, TTL: time.Hour, Clock: func() time.Time { return now.Add(24 * time.Hour) }}
	stale := NewDocs(later, "mem://directory", failing)
	if res := lookup(t, stale, "compute.instances.get", ""); res.Reference == nil {
		t.Errorf("stale lookup = %+v, want the cached reference", res)
	}
	if want := []string{"mem://directory", "mem://compute.v1"}; !slices.Equal(tried, want) {
		t.Errorf("the stale store tried %q, want %q", tried, want)
	}
}

// TestDocs_AdmissionFailureSkipsTheStaleCopy pins what the guide says about a download that distills but names
// another directory entry: the cache rejects it at admission and answers unavailable, without falling back to the
// stale copy on disk, because only a fetch or distill error takes that fallback.
func TestDocs_AdmissionFailureSkipsTheStaleCopy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	d, _ := newTestDocs(t, dir, func() time.Time { return now })
	if res := lookup(t, d, "compute.instances.get", ""); res.Reference == nil {
		t.Fatalf("seed lookup = %+v", res)
	}
	wrong := func(_ context.Context, url string) ([]byte, error) {
		if url == "mem://directory" {
			return []byte(testDirectory), nil
		}
		return fixture(t, "compute.stable"), nil // names compute stable, not compute v1.
	}
	later := cache.Config{Dir: dir, TTL: time.Hour, Clock: func() time.Time { return now.Add(24 * time.Hour) }}
	res := lookup(t, NewDocs(later, "mem://directory", wrong), "compute.instances.get", "")
	if res.Outcome != apiref.OutcomeUnavailable {
		t.Errorf("a download naming another entry = %+v, want unavailable", res)
	}
}

func TestReference_VersionFidelity(t *testing.T) {
	t.Parallel()
	const gap = "is not selected by the request path; the request may reach a different API version"
	for _, tc := range []struct {
		stem, id string
		gap      bool
	}{
		{"compute.v1", "compute.instances.get", false},                                    // v1 is a servicePath segment.
		{"compute.stable", "compute.instances.get", true},                                 // servicePath says v1.
		{"compute.preview", "compute.instances.get", true},                                // servicePath says v1.
		{"compute.preview", "compute.routers.preview", true},                              // "preview" is a literal, not the version.
		{"cloudresourcemanager.v3", "cloudresourcemanager.fetchResourceSemantics", false}, // v3:fetchResourceSemantics.
		{"cloudresourcemanager.v1", "cloudresourcemanager.projects.list", false},          // first segment v1.
		{"storage.v1", "storage.objects.get", false},                                      // no flatPath; servicePath.
	} {
		d := distilled(t, tc.stem)
		ref := buildReference(d, tc.id)
		got := slices.ContainsFunc(ref.Gaps, func(g string) bool { return strings.HasSuffix(g, gap) })
		if got != tc.gap {
			t.Errorf("%s %s: gap %v, want %v (gaps %q)", tc.stem, tc.id, got, tc.gap, ref.Gaps)
		}
	}
	// With no servicePath and no flatPath, the first segment of path names the version.
	d := &APIDoc{Name: "a", Version: "v2", RootURL: "https://a.googleapis.com/", Methods: map[string]DocMethod{
		"a.x.get": {HTTPMethod: "GET", Path: "v2/x"}, "a.y.get": {HTTPMethod: "GET", Path: "v1/v2"},
	}}
	if ref := buildReference(d, "a.x.get"); len(ref.Gaps) != 0 {
		t.Errorf("path v2/x gaps = %q, want none", ref.Gaps)
	}
	if ref := buildReference(d, "a.y.get"); len(ref.Gaps) != 1 {
		t.Errorf("path v1/v2 gaps = %q, want the version gap", ref.Gaps)
	}
}

func TestDocs_SharedFileStemAdmitsOnlyItsOwnDocument(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Name "a.b" version "v1" and name "a" version "b.v1" both name the file a.b.v1.json.
	m := &memFetch{t: t}
	d := NewDocs(cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now}, "mem://directory", m.fetch)
	first := d.docCache(directoryItem{Name: "a.b", Version: "v1", DiscoveryRestURL: "mem://compute.v1"})
	second := d.docCache(directoryItem{Name: "a", Version: "b.v1", DiscoveryRestURL: "mem://compute.v1"})
	if first == second {
		t.Fatal("two directory entries share one cache")
	}
	if first.DataPath != second.DataPath || filepath.Base(first.DataPath) != "a.b.v1.json" {
		t.Fatalf("paths %s and %s, want one shared stem a.b.v1", first.DataPath, second.DataPath)
	}
	// The fixture names compute v1, so neither entry admits it.
	if first.Get(t.Context()) != nil || second.Get(t.Context()) != nil {
		t.Error("a document that names another entry was admitted")
	}
}

func TestDocs_ReferenceBasics(t *testing.T) {
	t.Parallel()
	d, _ := newTestDocs(t, t.TempDir(), time.Now)
	res := lookup(t, d, "compute.instances.get", "")
	ref := res.Reference
	if res.Outcome != apiref.OutcomeFound || ref.Connector != "gcp" || ref.Protocol != "rest-json" ||
		ref.Method != http.MethodGet || ref.Endpoint != "https://compute.googleapis.com" ||
		ref.PathTemplate != "/compute/v1/projects/{project}/zones/{zone}/instances/{instance}" ||
		ref.Summary != "Returns the specified Instance resource." || ref.AuthField != "gcp_auth" ||
		ref.AuthArgs["service"] != "compute" || ref.Source.Name != "Google API Discovery" ||
		ref.Source.Document != "compute v1" || ref.Source.Version != "20260922" || len(ref.Source.SHA256) != 64 {
		t.Errorf("compute.instances.get = %+v", res)
	}
	// compute's stable label never appears in its paths, which all say v1.
	res = lookup(t, d, "compute.instances.get", "stable")
	want := []string{
		"version stable is not selected by the request path; the request may reach a different API version",
	}
	if res.Outcome != apiref.OutcomeIncomplete || !slices.Equal(res.Reference.Gaps, want) {
		t.Errorf("stable = %+v, want the wire-fidelity gap", res)
	}
	// A www.googleapis.com API signs as its directory name, as the gate resolves it.
	res = lookup(t, d, "synth.things.list", "")
	if res.Reference.Endpoint != "https://www.googleapis.com" || res.Reference.AuthArgs["service"] != "synth" ||
		res.Reference.PathTemplate != "/synth/v1/things" {
		t.Errorf("synth.things.list = %+v", res.Reference)
	}
}

func TestSafePart(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"compute": true, "gamesConfiguration": true, "v1.1": true, "directory_v1": true, "2026-09-01": true,
		".": false, "..": false, "": false, "a/b": false, `a\b`: false, "v1\t": false,
	} {
		if got := safePart(s); got != want {
			t.Errorf("safePart(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	got := []string{"v10", "v2", "v1", "v3"}
	slices.SortFunc(got, compareVersions)
	if want := []string{"v1", "v2", "v3", "v10"}; !slices.Equal(got, want) {
		t.Errorf("sorted = %q, want %q", got, want)
	}
}

func TestDistillDirectory(t *testing.T) {
	t.Parallel()
	d, err := distillDirectory([]byte(`{"kind":"discovery#directoryList","items":[{"name":"compute","version":"v1",` +
		`"discoveryRestUrl":"u","title":"Compute","preferred":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(
		serializeDirectory(d),
	); got != `{"items":[{"name":"compute","version":"v1","discoveryRestUrl":"u"}]}` {
		t.Errorf("serialized = %s", got)
	}
	if _, derr := distillDirectory([]byte("[")); !errors.Is(derr, ErrDocsRejected) {
		t.Errorf("malformed err = %v", derr)
	}
	if aerr := admitDirectory(&directoryResponse{}); !errors.Is(aerr, ErrDocsRejected) {
		t.Errorf("empty err = %v", aerr)
	}
}

func TestPickMethod(t *testing.T) {
	t.Parallel()
	doc := func(version string, ids ...string) *APIDoc {
		d := &APIDoc{Name: "a", Version: version, Methods: map[string]DocMethod{}}
		for _, id := range ids {
			d.Methods[id] = DocMethod{}
		}
		return d
	}
	// An exact match in one version outranks a folded one in another.
	if got, id, res := pickMethod([]*APIDoc{doc("v1", "a.B.c"), doc("v2", "a.b.c")}, "a.b.c"); res != nil ||
		got.Version != "v2" || id != "a.b.c" {
		t.Errorf("exact over folded = %v %q %+v", got, id, res)
	}
	res := func(docs ...*APIDoc) *apiref.Result {
		_, _, r := pickMethod(docs, "a.b.c")
		return r
	}
	if r := res(doc("v1", "a.B.c"), doc("v2", "a.b.C")); r == nil || r.Outcome != apiref.OutcomeAmbiguous ||
		!slices.Equal(r.Choices, []string{"v1", "v2"}) {
		t.Errorf("folded in two versions = %+v, want the versions as choices", r)
	}
	if r := res(doc("v1", "a.B.c", "a.b.C")); r == nil || r.Outcome != apiref.OutcomeAmbiguous ||
		r.Reason != "several operations differ only by case" || !slices.Equal(r.Choices, []string{"a.B.c", "a.b.C"}) {
		t.Errorf("folded twice in one version = %+v, want the ids as choices", r)
	}
}
