package azure

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/cache"
)

const compatRoot = "testdata/specs"

// compatCommit is the specs commit the fixtures were trimmed from (testdata/specs/README.md).
const compatCommit = "67d29f055c6c0ca0ff8262181837b1e9fc049c4a"

// compatSource serves the fixtures as a specSource: an index built from their listing, and their bodies.
type compatSource struct {
	ix      *Index
	listing *Listing
	bodies  map[string][]byte // path -> body
}

func (s *compatSource) Index(context.Context) (*Index, error) { return s.ix, nil }

func (s *compatSource) File(_ context.Context, _ string, f IndexFile) ([]byte, error) {
	b, ok := s.bodies[f.Path]
	if !ok {
		return nil, fmt.Errorf("%w: no fixture %s", fs.ErrNotExist, f.Path)
	}

	return b, nil
}

func (s *compatSource) Summary(ctx context.Context, sha string, f IndexFile, b *Budget) (*FileSummary, error) {
	body, err := s.File(ctx, sha, f)
	if err != nil {
		return nil, err
	}
	if e := b.Charge(int64(len(body))); e != nil {
		return nil, e
	}

	return Summarize(body)
}

func compatFixtures(t *testing.T) *compatSource {
	t.Helper()
	src := &compatSource{bodies: map[string][]byte{}}
	l := &Listing{SHA: compatCommit}
	err := filepath.WalkDir(filepath.Join(compatRoot, "specification"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(compatRoot, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		src.bodies[rel] = body
		l.Entries = append(l.Entries, ListingEntry{Path: rel, Blob: gitBlobID(body)})

		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	src.listing = l
	src.ix, err = BuildIndex(l)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}

	return src
}

func compatCatalog(t *testing.T) Catalog {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(compatRoot, "catalog.json"))
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	data, err := parseCatalogData(raw)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}

	return newCatalog(func(context.Context) (CatalogData, error) { return *data, nil })
}

// compatPeek is the gate view the docs get: a snapshot of the fixture catalog that fails the test if it fetches.
func compatPeek(t *testing.T) func() Catalog {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(compatRoot, "catalog.json"))
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	data, err := parseCatalogData(raw)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	c := newCatalog(func(context.Context) (CatalogData, error) {
		t.Error("the gate catalog's fetch was called")

		return CatalogData{}, errors.New("unreachable")
	})
	c.peek = func() *CatalogData { return data }

	return c.PeekSnapshot
}

// compatPlaceholder matches a placeholder of the emitted URL: <name> or <name+>, either marked :unrendered.
var compatPlaceholder = regexp.MustCompile(`<([^<>:+]+)\+?(?::unrendered)?>`)

// fillTemplate fills the URL the tool emits, built by apiref.TemplateURL, the same builder the tool uses, the way the
// model is told to: each placeholder from values, else "x1". Values are given in wire form.
func fillTemplate(ref *apiref.Reference, values map[string]string) string {
	return compatPlaceholder.ReplaceAllStringFunc(apiref.TemplateURL(ref), func(m string) string {
		if v, ok := values[compatPlaceholder.FindStringSubmatch(m)[1]]; ok {
			return v
		}

		return "x1"
	})
}

type compatCase struct {
	service, operation string
	values             map[string]string // label or query input -> value
	authService        string            // the azure_auth.service to send when the template's is a placeholder
	wantGap            bool              // the docs' gate check reports the denial, and it is the only gap
	wantErr            error             // what Provider.AuthorizeAction returns on the filled template
}

func checkGateCompat(t *testing.T, src *compatSource, reader *Provider, tc compatCase) {
	t.Helper()
	d := NewDocs(src, "https://management.azure.com", compatPeek(t))
	res := d.Reference(t.Context(), apiref.Query{Connector: "azure", Service: tc.service, Operation: tc.operation})
	if res.Reference == nil {
		t.Fatalf("Reference = %+v, want a reference", res)
	}
	ref := res.Reference
	// The exact outcome: found with no gap at all, or, for a known denial, incomplete with the gate's gap as
	// the only gap. Any other gap is a renderer defect the template would carry to the model.
	want := apiref.OutcomeFound
	if tc.wantGap {
		want = apiref.OutcomeIncomplete
	}
	gateGaps := 0
	for _, g := range ref.Gaps {
		if strings.HasPrefix(g, gateDeniesPrefix) {
			gateGaps++
		}
	}
	if res.Outcome != want || gateGaps != len(ref.Gaps) || (gateGaps == 1) != tc.wantGap {
		t.Fatalf("outcome %s (want %s), gaps %v, limitations %v", res.Outcome, want, ref.Gaps, ref.Limitations)
	}
	service := ref.AuthArgs["service"]
	if tc.authService != "" {
		if service != namespacePlaceholder {
			t.Fatalf(
				"service = %q, want the placeholder %q for a path whose namespace an input sets",
				service,
				namespacePlaceholder,
			)
		}
		service = tc.authService
	}
	u := fillTemplate(ref, tc.values)
	err := reader.AuthorizeAction(t.Context(), providerView(t, ref.Method, u), azArgs(t, service))
	if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
		t.Fatalf("AuthorizeAction(%s %s, service %s) = %v, want %v", ref.Method, u, service, err, tc.wantErr)
	}
}

func TestGateCompatibility(t *testing.T) {
	t.Parallel()
	src := compatFixtures(t)
	cases := []compatCase{
		{"Microsoft.Compute", "VirtualMachines_ListAll", nil, "", false, nil},
		{"Microsoft.Compute", "VirtualMachines_List", nil, "", false, nil},
		{"Microsoft.Compute", "VirtualMachines_ListByLocation", nil, "", true, ErrActionUnresolved},
		{"Microsoft.Resources", "ResourceGroups_List", nil, "", false, nil},
		{
			"Microsoft.Resources", "Resources_Get",
			map[string]string{
				"resourceProviderNamespace": "Microsoft.Compute", "parentResourcePath": "virtualMachines/vm1",
				"resourceType": "extensions", "resourceName": "ext1", "api-version": "2026-04-01",
			},
			"Microsoft.Compute", false, nil,
		},
		{"Microsoft.Storage", "StorageAccounts_ListKeys", nil, "", false, ErrActionDenied},
		{
			"Microsoft.Authorization",
			"RoleAssignments_GetById",
			map[string]string{
				"roleAssignmentId": "subscriptions/s1/providers/Microsoft.Authorization/roleAssignments/a1",
			},
			"Microsoft.Authorization",
			false,
			nil,
		},
		{
			"Microsoft.Authorization", "RoleAssignments_ListForScope",
			map[string]string{"scope": "subscriptions/s1"},
			"", false, nil,
		},
		{
			"Microsoft.Authorization", "RoleDefinitions_GetById",
			map[string]string{"roleId": "subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/d1"},
			"Microsoft.Authorization", false, nil,
		},
		{"Microsoft.KeyVault", "Vaults_List", nil, "", false, nil},
	}
	reader := NewProvider(compatCatalog(t), NewRoleEvaluator(RolePermissions{Actions: []string{"*/read"}}), "Reader")
	for _, tc := range cases {
		t.Run(tc.operation, func(t *testing.T) {
			t.Parallel()
			checkGateCompat(t, src, reader, tc)
		})
	}
}

// TestOfflineWithAWarmCache pins offline use with the real store: one lookup online fills the index, the summaries
// and the files on disk, and a second store over the same directory answers the same lookup while the listing and
// every raw download fail, as with the metadata origins unreachable after startup.
func TestOfflineWithAWarmCache(t *testing.T) {
	t.Parallel()
	src := compatFixtures(t)
	dir := t.TempDir()
	prefix := "/Azure/azure-rest-api-specs/" + compatCommit + "/"
	online := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		p, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), prefix))
		if b, ok := src.bodies[p]; err == nil && ok {
			return fakeResponse(r, http.StatusOK, b), nil
		}

		return fakeResponse(r, http.StatusNotFound, nil), nil
	})
	offline := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errTransport })
	type listingFunc = func(context.Context, *http.Client, string) (*Listing, error)
	failing := func(context.Context, *http.Client, string) (*Listing, error) { return nil, errTransport }
	lookup := func(rt http.RoundTripper, listing listingFunc) apiref.Result {
		s := NewSpecStore(SpecStoreConfig{
			Cache:  cache.Config{Dir: dir, TTL: time.Hour, Clock: time.Now},
			Client: &http.Client{Transport: rt}, RepoURL: testRepoURL, RawBase: SpecsRawBase,
			Listing: listing, Summarize: Summarize,
		})

		return NewDocs(s, "https://management.azure.com", compatPeek(t)).Reference(t.Context(),
			apiref.Query{Connector: "azure", Service: "Microsoft.Compute", Operation: "VirtualMachines_List"})
	}
	first := lookup(online, staticListing(src.listing))
	if first.Outcome != apiref.OutcomeFound {
		t.Fatalf("online lookup = %+v", first)
	}
	again := lookup(offline, failing)
	if again.Outcome != apiref.OutcomeFound || again.Reference.PathTemplate != first.Reference.PathTemplate ||
		apiref.TemplateURL(again.Reference) != apiref.TemplateURL(first.Reference) {
		t.Fatalf("offline lookup = %+v, want the online answer", again)
	}
}

func TestGateCompatibilityVaultsListSendsItsOwnVersion(t *testing.T) {
	t.Parallel()
	d := NewDocs(compatFixtures(t), "https://management.azure.com", compatPeek(t))
	res := d.Reference(t.Context(),
		apiref.Query{Connector: "azure", Service: "Microsoft.KeyVault", Operation: "Vaults_List"})
	if res.Reference == nil {
		t.Fatalf("Reference = %+v", res)
	}
	u := fillTemplate(res.Reference, nil)
	if !strings.Contains(u, "api-version=2015-11-01") || strings.Contains(u, "api-version=2026-05-15") {
		t.Fatalf("Vaults_List URL = %s, want the enum's api-version 2015-11-01", u)
	}
	if res.Reference.AuthArgs["service"] != "Microsoft.Resources" {
		t.Fatalf("service = %q, want the path-derived Microsoft.Resources", res.Reference.AuthArgs["service"])
	}
}
