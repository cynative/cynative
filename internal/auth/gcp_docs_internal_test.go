package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
	"github.com/cynative/cynative/internal/cache"
)

// peekCatalog is a fakeCatalog whose loaded snapshot holds idx for compute.
type peekCatalog struct {
	fakeCatalog

	idx gcphardening.MethodIndex
}

func (c peekCatalog) PeekMethodIndex(service string) (gcphardening.MethodIndex, bool) {
	return c.idx, service == "compute" && c.idx != nil
}

// gcpComputeIndex is the gate's view of two compute v1 methods.
func gcpComputeIndex() gcphardening.MethodIndex {
	return gcphardening.MethodIndex{
		"compute.instances.list": {
			ID: "compute.instances.list", HTTPMethod: "GET", ServicePath: "compute/v1/",
			FlatPath: "projects/{project}/zones/{zone}/instances",
		},
		"compute.instances.get": {
			ID: "compute.instances.get", HTTPMethod: "GET", ServicePath: "compute/v1/",
			FlatPath: "projects/{project}/zones/{zone}/instances/{instance}",
		},
	}
}

// docsFetch serves a one-entry directory and the compute v1 fixture, and records what it was asked for.
type docsFetch struct {
	mu   sync.Mutex
	urls []string
}

func (f *docsFetch) fetch(_ context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	f.urls = append(f.urls, url)
	f.mu.Unlock()
	switch url {
	case gcphardening.DefaultDiscoveryDirectoryURL:
		return []byte(
			`{"items":[{"name":"compute","version":"v1","discoveryRestUrl":"https://doc.example/compute"}]}`,
		), nil
	case "https://doc.example/compute":
		return os.ReadFile(filepath.Join("gcp", "testdata", "discovery", "compute.v1.json"))
	}
	return nil, errors.New("unexpected url " + url)
}

// noBootstrap is a lazy credential bootstrap that fails the test if anything runs it.
func noBootstrap(t *testing.T) func(context.Context) error {
	t.Helper()
	return func(context.Context) error {
		t.Error("the credential bootstrap ran")
		return nil
	}
}

func TestGCPProvider_ReferenceUnconfigured(t *testing.T) {
	t.Parallel()
	res := newTestGCPProvider(nil).Reference(t.Context(), apiref.Query{Connector: "gcp", Operation: "compute.x.y"})
	if res.Outcome != apiref.OutcomeUnavailable || res.Reason != "GCP API metadata is not configured" {
		t.Errorf("bare provider = %+v", res)
	}
}

func TestGCPProvider_ReferenceNeverBootstraps(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := &docsFetch{}
	p := newGCPProvider(fakeCatalog{}, noBootstrap(t))
	p.docs = newGCPDocs(cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now}, f.fetch)
	res := LookupReference(t.Context(), []Provider{p},
		apiref.Query{Connector: "gcp", Operation: "compute.instances.list"})
	if res.Outcome != apiref.OutcomeFound || res.Reference.AuthArgs["service"] != "compute" {
		t.Fatalf("reference = %+v", res)
	}
	if want := []string{
		gcphardening.DefaultDiscoveryDirectoryURL,
		"https://doc.example/compute",
	}; !slices.Equal(
		f.urls,
		want,
	) {
		t.Errorf("fetched %q, want %q", f.urls, want)
	}
	for _, name := range []string{"directory.json", "compute.v1.json"} {
		if _, err := os.Stat(filepath.Join(dir, "docs", name)); err != nil {
			t.Errorf("docs cache file %s: %v", name, err)
		}
	}
}

func TestGCPProvider_Hint(t *testing.T) {
	t.Parallel()
	view := authreq.View{
		Method: "GET", Path: "/compute/v1/projects/p/zones/z/instancez",
		EscapedPath: "/compute/v1/projects/p/zones/z/instancez",
	}
	um := &authreq.UnmatchedRequestError{Service: "compute", Err: errors.New("gate")}
	p := newGCPProvider(peekCatalog{idx: gcpComputeIndex()}, noBootstrap(t))
	h := p.Hint(t.Context(), view, um)
	if want := []string{
		"compute.instances.list (GET /compute/v1/projects/{project}/zones/{zone}/instances)",
	}; !slices.Equal(h.Candidates, want) ||
		h.Operation != "compute.instances.list" ||
		h.Note != gcphardening.HintNote {
		t.Errorf("hint = %+v", h)
	}
	p.catalog = peekCatalog{}
	if none := p.Hint(t.Context(), view, um); none.Candidates != nil || none.Note != gcphardening.HintNote {
		t.Errorf("hint with no snapshot = %+v, want only the note", none)
	}
}

func TestGCPExplainUnmatched(t *testing.T) {
	t.Parallel()
	p := newGCPProvider(peekCatalog{idx: gcpComputeIndex()}, noBootstrap(t))
	view := authreq.View{
		Method: "GET", Path: "/compute/v1/projects/p/zones/z/instancez",
		EscapedPath: "/compute/v1/projects/p/zones/z/instancez",
	}
	gate := errors.New("auth: authorize action for provider gcp: gcp_hardening: cannot identify method from " +
		"request: no method matches GET /compute/v1/projects/p/zones/z/instancez")
	err := ExplainUnmatched(t.Context(), "gcp", view, []Provider{p},
		&authreq.UnmatchedRequestError{Service: "compute", Err: gate})
	want := "auth: authorize action for provider gcp: gcp_hardening: cannot identify method from request: no " +
		"method matches GET /compute/v1/projects/p/zones/z/instancez. GET " +
		`"/compute/v1/projects/p/zones/z/instancez" on gcp/compute matched no operation in the cached API ` +
		"metadata. The gate stopped before attaching credentials or sending anything; this says nothing about " +
		"the principal's permissions. Check the request shape against the operation reference. Candidates: " +
		"compute.instances.list (GET /compute/v1/projects/{project}/zones/{zone}/instances). " +
		gcphardening.HintNote + " For an operation's request template call api_reference with " +
		`{"connector":"gcp","operation":"compute.instances.list","service":"compute"}.`
	if err.Error() != want {
		t.Errorf("message:\n%s\nwant:\n%s", err, want)
	}
	if !errors.Is(err, gate) {
		t.Error("the gate error is no longer reachable")
	}
	if strings.Contains(err.Error(), "\n") {
		t.Error("the message spans lines")
	}
}
