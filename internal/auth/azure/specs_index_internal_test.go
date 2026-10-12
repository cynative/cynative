package azure

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

const (
	testSHA      = "0123456789abcdef0123456789abcdef01234567"
	computeNew   = "specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/compute.json"
	computeOld   = "specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2023-03-01/compute.json"
	computePrev  = "specification/compute/resource-manager/Microsoft.Compute/Compute/preview/2024-07-01/compute.json"
	diskNew      = "specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/disk.json"
	webClassic   = "specification/web/resource-manager/Microsoft.Web/stable/2024-04-01/WebApps.json"
	insightsLow  = "specification/monitor/resource-manager/microsoft.insights/Monitor/stable/2024-01-01/a.json"
	insightsUp   = "specification/monitor/resource-manager/Microsoft.Insights/Monitor/stable/2024-01-01/b.json"
	commonTypesP = "specification/common-types/resource-management/v5/types.json"
	localCommon  = "specification/compute/resource-manager/Microsoft.Compute/Compute/common-types/v1/common.json"
)

func listingOf(paths ...string) *Listing {
	l := &Listing{SHA: testSHA}
	for _, p := range paths {
		l.Entries = append(l.Entries, ListingEntry{Path: p, Blob: fakeBlob(p).String()})
	}

	return l
}

// TestBuildIndex_GroupsOperationFilesAndKeepsRefTargets pins the structure: namespaces keyed lower-case, groups
// per layout, dirs newest first with stable before preview, files by path, and the ref-target map.
func TestBuildIndex_GroupsOperationFilesAndKeepsRefTargets(t *testing.T) {
	t.Parallel()
	ix, err := BuildIndex(listingOf(diskNew, computeOld, computePrev, computeNew, webClassic, insightsLow,
		insightsUp, commonTypesP, localCommon,
		"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/examples/x.json",
		"specification/compute/data-plane/Microsoft.Compute/stable/2024-07-01/dp.json",
		"README.md",
	))
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	compute := ix.Namespaces["microsoft.compute"]
	if compute == nil || compute.Name != "Microsoft.Compute" {
		t.Fatalf("compute namespace = %+v", compute)
	}
	dirs := compute.Groups["compute/Compute"].Dirs
	gotDirs := make([]string, 0, len(dirs))
	for _, d := range dirs {
		gotDirs = append(gotDirs, d.Kind+"/"+d.Name)
	}
	if want := []string{"stable/2024-07-01", "preview/2024-07-01", "stable/2023-03-01"}; !slices.Equal(gotDirs, want) {
		t.Errorf("dirs = %q, want %q", gotDirs, want)
	}
	if files := dirs[0].Files; len(files) != 2 || files[0].Path != computeNew || files[1].Path != diskNew ||
		files[0].Blob != fakeBlob(computeNew).String() {
		t.Errorf("newest stable files = %+v", files)
	}
	if web := ix.Namespaces["microsoft.web"]; web == nil || web.Groups["web"] == nil {
		t.Errorf("classic layout group missing: %+v", web)
	}
	if ins := ix.Namespaces["microsoft.insights"]; ins == nil || ins.Name != "Microsoft.Insights" {
		t.Errorf("insights spelling = %+v", ins)
	}
	for _, p := range []string{computeNew, commonTypesP, localCommon} {
		if ix.Refs[p] != fakeBlob(p).String() {
			t.Errorf("ref target %s missing", p)
		}
	}
	for p := range ix.Refs {
		if strings.Contains(p, "/examples/") || strings.Contains(p, "data-plane") || p == "README.md" {
			t.Errorf("ref target %s should be excluded", p)
		}
	}
	if len(ix.Namespaces) != 3 {
		t.Errorf("namespaces = %d, want 3", len(ix.Namespaces))
	}
}

// TestParseOpPath pins each layout rule.
func TestParseOpPath(t *testing.T) {
	t.Parallel()
	longNS205 := "Microsoft." + strings.Repeat("N", 195)
	ok := map[string]opFile{
		computeNew: {
			namespace: "Microsoft.Compute", group: "compute/Compute", kind: kindStable, dir: "2024-07-01",
			file: "compute.json",
		},
		webClassic: {
			namespace: "Microsoft.Web",
			group:     "web",
			kind:      kindStable,
			dir:       "2024-04-01",
			file:      "WebApps.json",
		},
		"specification/x/resource-manager/" + longNS205 + "/stable/2024-07-01/c.json": {
			namespace: longNS205,
			group:     "x",
			kind:      kindStable,
			dir:       "2024-07-01",
			file:      "c.json",
		},
	}
	for p, want := range ok {
		if got, good := parseOpPath(p); !good || got != want {
			t.Errorf("parseOpPath(%q) = %+v, %v", p, got, good)
		}
	}
	longNS206 := "Microsoft." + strings.Repeat("N", 196)
	bad := []string{
		"specification/examples/resource-manager/Microsoft.X/stable/2024-07-01/c.json",
		"specification/x/resource-manager/Microsoft.X/examples/stable/2024-07-01/c.json",
		"specification/compute/resource-manager/Microsoft.Compute/stable/2024-07-01/examples/x.json",
		"specification/compute/resource-manager/Microsoft.Compute/Compute/beta/2024-07-01/c.json",
		"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/v1/c.json",
		"specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/c.yaml",
		"specification/compute/resource-manager/Microsoft.Compute.Admin/Compute/stable/2024-07-01/c.json",
		"specification/compute/resource-manager/compute/Compute/stable/2024-07-01/c.json",
		"specification/compute/resource-manager/Microsoft.Compute/Com pute/stable/2024-07-01/c.json",
		"specification/compute/data-plane/Microsoft.Compute/Compute/stable/2024-07-01/c.json",
		"other/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/c.json",
		"specification/compute/resource-manager/Microsoft.Compute/stable/c.json",
		"specification/a/resource-manager/Microsoft.X/S/stable/2024-07-01/deep/c.json",
		// Every part fits its grammar, but the selector would pass apiref.MaxChoice.
		"specification/" + strings.Repeat("s", 90) + "/resource-manager/Microsoft.X/" + strings.Repeat("v", 90) +
			"/stable/2024-07-01/c.json",
		// namespace over 205 bytes
		"specification/x/resource-manager/" + longNS206 + "/stable/2024-07-01/c.json",
	}
	for _, p := range bad {
		if got, good := parseOpPath(p); good {
			t.Errorf("parseOpPath(%q) = %+v, want refused", p, got)
		}
	}
}

// TestRefTarget_AdmitsEveryOperationFile pins that the ref-segment grammar is no narrower than the operation
// grammar: the longest file name parseOpPath admits is also a ref target, so BuildIndex never drops it.
func TestRefTarget_AdmitsEveryOperationFile(t *testing.T) {
	t.Parallel()
	p := "specification/x/resource-manager/Microsoft.X/stable/2024-07-01/" + strings.Repeat("f", 175) + ".json"
	if _, ok := parseOpPath(p); !ok {
		t.Fatalf("parseOpPath refused a 180-byte file name")
	}
	if !refTarget(p) {
		t.Fatalf("refTarget refused a file parseOpPath admits")
	}
	// selector at exactly 200 passes (x@stable/2024-07-01/ + 180-byte filename), 201 refuses
	p200 := "specification/x/resource-manager/Microsoft.X/stable/2024-07-01/" + strings.Repeat("f", 175) + ".json"
	p201 := "specification/x/resource-manager/Microsoft.X/stable/2024-07-01/" + strings.Repeat("f", 176) + ".json"
	if _, ok := parseOpPath(p200); !ok {
		t.Errorf("parseOpPath refused 200-byte selector")
	}
	if _, ok := parseOpPath(p201); ok {
		t.Errorf("parseOpPath accepted 201-byte selector")
	}
	// refSegmentPattern at 205 passes, 206 refuses
	seg205 := strings.Repeat("x", 205)
	seg206 := strings.Repeat("x", 206)
	if !refSegmentPattern.MatchString(seg205) {
		t.Errorf("refSegmentPattern refused 205-byte segment")
	}
	if refSegmentPattern.MatchString(seg206) {
		t.Errorf("refSegmentPattern accepted 206-byte segment")
	}
}

// TestBuildIndex_Refusals pins the listing-level refusals.
func TestBuildIndex_Refusals(t *testing.T) {
	t.Parallel()
	badBlobNonRef := listingOf(computeNew, "README.md")
	badBlobNonRef.Entries[1].Blob = "XYZ"
	badBlobRefOnly := listingOf(computeNew, commonTypesP)
	badBlobRefOnly.Entries[1].Blob = "XYZ"
	cases := map[string]struct {
		listing *Listing
		errText string
	}{
		"bad commit":        {&Listing{SHA: "nope", Entries: listingOf(computeNew).Entries}, "commit id"},
		"bad blob non-ref":  {badBlobNonRef, "blob id of"},
		"bad blob ref-only": {badBlobRefOnly, "blob id of"},
		"no ops":            {listingOf(commonTypesP), "no valid commit or no namespace"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := BuildIndex(c.listing)
			if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), c.errText) {
				t.Fatalf("err = %v, want ErrSpecsRejected with %q", err, c.errText)
			}
		})
	}
}

// TestIndex_SerializeRoundTrips pins that a serialized index reads back and passes admission.
func TestIndex_SerializeRoundTrips(t *testing.T) {
	t.Parallel()
	ix, err := BuildIndex(listingOf(computeNew, webClassic, commonTypesP))
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	var back *Index
	back, err = unmarshalIndex(ix.Serialize())
	if err != nil || admitIndex(back) != nil || back.SHA != testSHA || len(back.Namespaces) != 2 {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	_, err = unmarshalIndex([]byte("{"))
	if !errors.Is(err, ErrSpecsRejected) {
		t.Errorf("bad JSON: err = %v", err)
	}
}

// TestAdmitIndex_RefusesATamperedCache pins admission over a cached index whose structure was edited: every
// association a lookup trusts is re-checked.
func TestAdmitIndex_RefusesATamperedCache(t *testing.T) {
	t.Parallel()
	mutate := map[string]func(m map[string]any){
		"bad commit":    func(m map[string]any) { m["sha"] = "x" },
		"no namespaces": func(m map[string]any) { m["namespaces"] = map[string]any{} },
		"bad ref path":  func(m map[string]any) { refs(m)["../../etc/passwd.json"] = fakeBlob("x").String() },
		"bad ref blob":  func(m map[string]any) { refs(m)[computeNew] = "XYZ" },
		"null namespace": func(m map[string]any) {
			m["namespaces"].(map[string]any)["microsoft.compute"] = nil
		},
		"key mismatch": func(m map[string]any) { ns(m)["name"] = "Microsoft.Network" },
		"bad name":     func(m map[string]any) { ns(m)["name"] = "microsoft.compute!" },
		"no groups":    func(m map[string]any) { ns(m)["groups"] = map[string]any{} },
		"null group":   func(m map[string]any) { groups(m)["compute/Compute"] = nil },
		"no dirs":      func(m map[string]any) { groups(m)["compute/Compute"] = map[string]any{"dirs": []any{}} },
		"unsorted dirs": func(m map[string]any) {
			d := dirs(m)
			d[0], d[1] = d[1], d[0]
		},
		"no files":    func(m map[string]any) { dir0(m)["files"] = []any{} },
		"moved file":  func(m map[string]any) { file0(m)["path"] = diskNew },
		"wrong kind":  func(m map[string]any) { dir0(m)["kind"] = kindPreview },
		"wrong group": func(m map[string]any) { groups(m)["compute/Other"] = groups(m)["compute/Compute"] },
		"blob differs from ref": func(m map[string]any) {
			file0(m)["blob"] = fakeBlob("other").String()
		},
		"file not a ref": func(m map[string]any) { delete(refs(m), computeNew) },
		"empty blob no ref": func(m map[string]any) {
			file0(m)["blob"] = ""
			delete(refs(m), computeNew)
		},
		"empty blob": func(m map[string]any) {
			file0(m)["blob"] = ""
			refs(m)[computeNew] = ""
		},
		"refs null": func(m map[string]any) { m["refs"] = nil },
		"duplicate dirs": func(m map[string]any) {
			d := dirs(m)
			d = append(d, d[0])
			groups(m)["compute/Compute"].(map[string]any)["dirs"] = d
		},
		"duplicate files": func(m map[string]any) {
			files := dir0(m)["files"].([]any)
			dir0(m)["files"] = append(files, files[0])
		},
	}
	for name, f := range mutate {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ix, err := BuildIndex(listingOf(computeNew, computeOld, commonTypesP))
			if err != nil {
				t.Fatalf("BuildIndex: %v", err)
			}
			var m map[string]any
			if err = json.Unmarshal(ix.Serialize(), &m); err != nil {
				t.Fatalf("decode: %v", err)
			}
			f(m)
			raw, _ := json.Marshal(m)
			var back *Index
			back, err = unmarshalIndex(raw)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			err = admitIndex(back)
			if !errors.Is(err, ErrSpecsRejected) {
				t.Fatalf("admitIndex = %v, want ErrSpecsRejected", err)
			}
		})
	}
}

func refs(m map[string]any) map[string]any { return m["refs"].(map[string]any) }

func ns(m map[string]any) map[string]any {
	return m["namespaces"].(map[string]any)["microsoft.compute"].(map[string]any)
}

func groups(m map[string]any) map[string]any { return ns(m)["groups"].(map[string]any) }

func dirs(m map[string]any) []any {
	return groups(m)["compute/Compute"].(map[string]any)["dirs"].([]any)
}

func dir0(m map[string]any) map[string]any { return dirs(m)[0].(map[string]any) }

func file0(m map[string]any) map[string]any { return dir0(m)["files"].([]any)[0].(map[string]any) }

// TestGrammars pins the input grammars from the spec.
func TestGrammars(t *testing.T) {
	t.Parallel()
	checks := []struct {
		name string
		fn   func(string) bool
		good []string
		bad  []string
	}{
		{
			"namespace", validNamespace,
			[]string{"Microsoft.Compute", "Anyscale.Platform", "A.B.C"},
			[]string{"Microsoft", "microsoft.", ".Compute", "Microsoft.Compute/x", "Micro soft.Compute", "1a.b"},
		},
		{
			"version", validVersion,
			[]string{"2024-07-01", "2025-01-01-preview", "2014-04-01-legacy", "2024-01-01-beta.1"},
			[]string{"2024-7-01", "v1", "2024-07-01-", "2024-07-01-Preview", "2024-07-01-1a"},
		},
		{
			"group part", validGroupPart,
			[]string{"compute", "Compute", "a.b_c-d", strings.Repeat("a", 100)},
			[]string{"", "-a", "a b", "a/b", strings.Repeat("a", 101)},
		},
		{
			"file",
			validFileName,
			[]string{"compute.json", "a-b_c.d.json", strings.Repeat("f", 200) + ".json"},
			[]string{".json", "a.yaml", "a b.json", "a/b.json", strings.Repeat("f", 201) + ".json"},
		},
		{"sha", validSHA, []string{testSHA}, []string{"", "0123", strings.ToUpper(testSHA), testSHA + "0"}},
		{"group id", validGroupID, []string{"compute", "compute/Compute"}, []string{"", "a/b/c", "a/", "/a"}},
	}
	for _, c := range checks {
		for _, s := range c.good {
			if !c.fn(s) {
				t.Errorf("%s(%q) = false, want true", c.name, s)
			}
		}
		for _, s := range c.bad {
			if c.fn(s) {
				t.Errorf("%s(%q) = true, want false", c.name, s)
			}
		}
	}
}
