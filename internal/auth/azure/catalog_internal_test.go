package azure

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

func fakeCatalogData() CatalogData {
	return CatalogData{
		Clouds: map[string]CloudEndpoints{
			"AzureCloud": {
				ResourceManager: "management.azure.com",
				Suffixes:        map[string]string{"storage": "core.windows.net", "keyVaultDns": "vault.azure.net"},
			},
			"AzureUSGovernment": {
				ResourceManager: "management.usgovcloudapi.net",
				Suffixes:        map[string]string{"storage": "core.usgovcloudapi.net"},
			},
			"AzureChinaCloud": {
				ResourceManager: "management.chinacloudapi.cn",
				Suffixes:        map[string]string{"storage": "core.chinacloudapi.cn"},
			},
		},
		Providers: map[string]ProviderOps{
			"Microsoft.Compute": {
				ResourceTypes: []string{"virtualMachines", "virtualMachines/extensions", "virtualMachines/runCommands"},
				Operations: []ProviderOperation{
					{Name: "Microsoft.Compute/virtualMachines/read", IsDataAction: false},
					{Name: "Microsoft.Compute/virtualMachines/write", IsDataAction: false},
					{Name: "Microsoft.Compute/virtualMachines/runCommand/action", IsDataAction: false},
				},
			},
			"Microsoft.DocumentDB": {
				ResourceTypes: []string{"databaseAccounts"},
				// The readonlykeys DUAL: registered as both /read and /action.
				Operations: []ProviderOperation{
					{Name: "Microsoft.DocumentDB/databaseAccounts/readonlykeys/read", IsDataAction: false},
					{Name: "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action", IsDataAction: false},
				},
			},
		},
	}
}

func fakeCatalog(t *testing.T) Catalog {
	t.Helper()
	data := fakeCatalogData()
	return newCatalog(func(context.Context) (CatalogData, error) { return data, nil })
}

func TestResolveCloud(t *testing.T) {
	t.Parallel()
	c := fakeCatalog(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		host      string
		wantCloud string
		wantErr   error
	}{
		{name: "public arm", host: "management.azure.com", wantCloud: "AzureCloud"},
		{name: "usgov arm", host: "management.usgovcloudapi.net", wantCloud: "AzureUSGovernment"},
		{name: "china arm", host: "management.chinacloudapi.cn", wantCloud: "AzureChinaCloud"},
		{name: "unknown host", host: "management.example.com", wantErr: ErrHostPattern},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := c.ResolveCloud(ctx, ParsedHost{Host: tc.host})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ResolveCloud(%q) err = %v, want %v", tc.host, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveCloud(%q): %v", tc.host, err)
			}
			if got.Cloud != tc.wantCloud || got.Host != tc.host {
				t.Errorf("ResolveCloud(%q) = %+v, want cloud=%q", tc.host, got, tc.wantCloud)
			}
		})
	}
}

func TestResourceTypes(t *testing.T) {
	t.Parallel()
	c := fakeCatalog(t)
	ctx := context.Background()

	got, err := c.ResourceTypes(ctx, "microsoft.compute") // case-insensitive namespace.
	if err != nil {
		t.Fatalf("ResourceTypes: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ResourceTypes len = %d, want 3 (%v)", len(got), got)
	}

	_, errFake := c.ResourceTypes(ctx, "Microsoft.Fake")
	if !errors.Is(errFake, ErrCatalogUnavailable) {
		t.Errorf("unknown namespace: want ErrCatalogUnavailable, got %v", errFake)
	}
}

func TestLookupOperation(t *testing.T) {
	t.Parallel()
	c := fakeCatalog(t)
	ctx := context.Background()

	// The readonlykeys DUAL: one (ns, typePath, token) registers two distinct
	// verbs (read + action) → ambiguity signal for the classifier.
	verbs, isData, err := c.LookupOperation(ctx, "Microsoft.DocumentDB", "databaseAccounts", "readonlykeys")
	if err != nil {
		t.Fatalf("LookupOperation: %v", err)
	}
	if len(verbs) != 2 {
		t.Fatalf("readonlykeys verbs = %v, want 2 distinct (read, action)", verbs)
	}
	for _, v := range verbs {
		if isData[v] {
			t.Errorf("verb %q should be isDataAction=false", v)
		}
	}

	// A single registered verb for a path → exactly one entry.
	verbs, _, err = c.LookupOperation(ctx, "Microsoft.Compute", "virtualMachines", "read")
	if err != nil {
		t.Fatalf("LookupOperation read: %v", err)
	}
	if len(verbs) != 1 || verbs[0] != "read" {
		t.Errorf("virtualMachines read verbs = %v, want [read]", verbs)
	}

	// Unknown namespace → ErrCatalogUnavailable.
	_, _, errNS := c.LookupOperation(ctx, "Microsoft.Fake", "widgets", "read")
	if !errors.Is(errNS, ErrCatalogUnavailable) {
		t.Errorf("unknown ns: want ErrCatalogUnavailable, got %v", errNS)
	}
}

// TestLookupOperationPrefixCollision pins the segment-anchored match: a token
// that is only a string-prefix of a longer verb segment must not fabricate a
// spurious verb. Without anchoring, token "read" would match
// ".../readMetadata/action" and inflate the verb set into a false ambiguity.
func TestLookupOperationPrefixCollision(t *testing.T) {
	t.Parallel()
	data := CatalogData{
		Providers: map[string]ProviderOps{
			"Microsoft.Compute": {
				ResourceTypes: []string{"virtualMachines"},
				Operations: []ProviderOperation{
					{Name: "Microsoft.Compute/virtualMachines/read", IsDataAction: false},
					{Name: "Microsoft.Compute/virtualMachines/readMetadata/action", IsDataAction: false},
				},
			},
		},
	}
	c := newCatalog(func(context.Context) (CatalogData, error) { return data, nil })
	verbs, _, err := c.LookupOperation(context.Background(), "Microsoft.Compute", "virtualMachines", "read")
	if err != nil {
		t.Fatalf("LookupOperation: %v", err)
	}
	if len(verbs) != 1 || verbs[0] != "read" {
		t.Errorf("prefix-collision verbs = %v, want [read] (readMetadata must not match)", verbs)
	}
}

func TestCatalogFetcherError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("fetch failed")
	c := newCatalog(func(context.Context) (CatalogData, error) { return CatalogData{}, sentinel })
	ctx := context.Background()

	if _, err := c.ResolveCloud(ctx, ParsedHost{Host: "management.azure.com"}); !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("ResolveCloud fetch error: want ErrCatalogUnavailable, got %v", err)
	}
	if _, err := c.ResourceTypes(ctx, "Microsoft.Compute"); !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("ResourceTypes fetch error: want ErrCatalogUnavailable, got %v", err)
	}
	if _, _, err := c.LookupOperation(
		ctx,
		"Microsoft.Compute",
		"virtualMachines",
		"read",
	); !errors.Is(
		err,
		ErrCatalogUnavailable,
	) {
		t.Errorf("LookupOperation fetch error: want ErrCatalogUnavailable, got %v", err)
	}
}

// TestParseEndpointsRejects2019Array proves the pure parser surfaces the 2019
// array shape as ErrCatalogUnavailable (the drift guard); the shell probe calls
// this.
func TestParseEndpointsRejects2019Array(t *testing.T) {
	t.Parallel()

	// 2022 object shape (accepted).
	obj := []byte(`{"resourceManager":"https://management.azure.com/","suffixes":{"storage":"core.windows.net"}}`)
	if _, err := parseCloudEndpoints(obj); err != nil {
		t.Fatalf("parseCloudEndpoints(object): %v", err)
	}
	// 2019 array shape (rejected).
	arr := []byte(`[{"resourceManager":"https://management.azure.com/"}]`)
	if _, err := parseCloudEndpoints(arr); !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("parseCloudEndpoints(2019 array): want ErrCatalogUnavailable, got %v", err)
	}
	// Object missing resourceManager (rejected).
	missing := []byte(`{"suffixes":{"storage":"core.windows.net"}}`)
	if _, err := parseCloudEndpoints(missing); !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("parseCloudEndpoints(missing resourceManager): want ErrCatalogUnavailable, got %v", err)
	}
	// Malformed JSON (rejected).
	bad := []byte(`{not valid json}`)
	if _, err := parseCloudEndpoints(bad); !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("parseCloudEndpoints(malformed json): want ErrCatalogUnavailable, got %v", err)
	}
}

func TestPruneActionVerbTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		ns    string
		types []string
		ops   []ProviderOperation
		want  []string
	}{
		{
			name:  "landmine dropped",
			ns:    "Microsoft.DocumentDB",
			types: []string{"databaseAccounts", "databaseAccounts/readonlykeys"},
			ops:   []ProviderOperation{{Name: "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action"}},
			want:  []string{"databaseAccounts"},
		},
		{
			name:  "genuine nested survives",
			ns:    "Microsoft.Compute",
			types: []string{"virtualMachines", "virtualMachines/extensions"},
			ops:   []ProviderOperation{{Name: "Microsoft.Compute/virtualMachines/read"}},
			want:  []string{"virtualMachines", "virtualMachines/extensions"},
		},
		{
			name:  "top-level survives despite coincidental action op",
			ns:    "Microsoft.OperationalInsights",
			types: []string{"querypacks"},
			ops:   []ProviderOperation{{Name: "Microsoft.OperationalInsights/querypacks/action"}},
			want:  []string{"querypacks"},
		},
		{
			name:  "leading slash edge kept",
			ns:    "Microsoft.Foo",
			types: []string{"/foo"},
			ops:   nil,
			want:  []string{"/foo"},
		},
		{
			name:  "deeper nesting landmine dropped",
			ns:    "Microsoft.Foo",
			types: []string{"a/b", "a/b/c"},
			ops:   []ProviderOperation{{Name: "Microsoft.Foo/a/b/c/action"}},
			want:  []string{"a/b"},
		},
		{
			name:  "action present but parent type absent kept",
			ns:    "Microsoft.Foo",
			types: []string{"foo/bar"},
			ops:   []ProviderOperation{{Name: "Microsoft.Foo/foo/bar/action"}},
			want:  []string{"foo/bar"},
		},
		{
			name:  "case-insensitive landmine dropped",
			ns:    "Microsoft.DocumentDB",
			types: []string{"DatabaseAccounts", "DatabaseAccounts/ReadonlyKeys"},
			ops:   []ProviderOperation{{Name: "microsoft.documentdb/databaseaccounts/readonlykeys/ACTION"}},
			want:  []string{"DatabaseAccounts"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := append([]string(nil), tc.types...)
			got := pruneActionVerbTypes(tc.ns, input, tc.ops)
			if !slices.Equal(got, tc.want) {
				t.Errorf("pruneActionVerbTypes = %v, want %v", got, tc.want)
			}
			if !slices.Equal(input, tc.types) {
				t.Errorf("input slice mutated: %v, want %v", input, tc.types)
			}
		})
	}
}

func TestFlattenProviderOps(t *testing.T) {
	t.Parallel()
	// JSON whitespace is insignificant; lines kept short (golines can't wrap string literals).
	raw := `{
"name":"Microsoft.DocumentDB",
"resourceTypes":[
{"name":"databaseAccounts","operations":[
{"name":"Microsoft.DocumentDB/databaseAccounts/read"}
]},
{"name":"databaseAccounts/readonlykeys","operations":[
{"name":"Microsoft.DocumentDB/databaseAccounts/readonlykeys/action"}
]},
{"name":"throughputPools","operations":[]}
],
"operations":[
{"name":"Microsoft.DocumentDB/register/action"}
]
}`
	var md providerOpsMetadata
	if err := json.Unmarshal([]byte(raw), &md); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := flattenProviderOps(md)
	if len(got.Operations) != 3 {
		t.Errorf("Operations = %d, want 3 (%v)", len(got.Operations), got.Operations)
	}
	wantTypes := []string{"databaseAccounts", "throughputPools"} // readonlykeys landmine pruned.
	if !slices.Equal(got.ResourceTypes, wantTypes) {
		t.Errorf("ResourceTypes = %v, want %v", got.ResourceTypes, wantTypes)
	}
}

func TestProviderOpsBase(t *testing.T) {
	t.Parallel()
	t.Run("single public cloud", func(t *testing.T) {
		t.Parallel()
		got := providerOpsBase(map[string]CloudEndpoints{
			"AzureCloud": {ResourceManager: "management.azure.com"},
		})
		if got != "https://management.azure.com" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("single sovereign cloud", func(t *testing.T) {
		t.Parallel()
		got := providerOpsBase(map[string]CloudEndpoints{
			"AzureChinaCloud": {ResourceManager: "management.chinacloudapi.cn"},
		})
		if got != "https://management.chinacloudapi.cn" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("empty map", func(t *testing.T) {
		t.Parallel()
		if got := providerOpsBase(map[string]CloudEndpoints{}); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

// TestBuildCatalog_SingleCloudNarrowing pins the host-pin==audience security
// property: with the catalog narrowed to one cloud, ResolveCloud accepts only that
// cloud's resourceManager host and fails closed for any other cloud's host.
func TestBuildCatalog_SingleCloudNarrowing(t *testing.T) {
	t.Parallel()

	clouds := map[string]string{"AzureUSGovernment": "https://management.usgovcloudapi.net/metadata/endpoints"}
	getEndpoints := func(context.Context, string) ([]byte, error) {
		return []byte(`{"resourceManager":"https://management.usgovcloudapi.net","suffixes":{"x":"y"}}`), nil
	}
	getOps := func(context.Context, string) (map[string]ProviderOps, error) {
		return map[string]ProviderOps{}, nil
	}
	data, err := buildCatalog(context.Background(), clouds, getEndpoints, getOps, "")
	if err != nil {
		t.Fatalf("buildCatalog: %v", err)
	}
	if _, ok := data.Clouds["AzureUSGovernment"]; !ok || len(data.Clouds) != 1 {
		t.Fatalf("Clouds = %v, want only AzureUSGovernment", data.Clouds)
	}

	c := newCatalog(func(context.Context) (CatalogData, error) { return data, nil })
	// A public-cloud host must be rejected when only the gov cloud is present.
	if _, rerr := c.ResolveCloud(context.Background(), ParsedHost{Host: "management.azure.com"}); !errors.Is(
		rerr, ErrHostPattern,
	) {
		t.Errorf("ResolveCloud(public host) err = %v, want ErrHostPattern", rerr)
	}
	got, rerr := c.ResolveCloud(context.Background(), ParsedHost{Host: "management.usgovcloudapi.net"})
	if rerr != nil || got.Cloud != "AzureUSGovernment" {
		t.Errorf("ResolveCloud(gov) = %+v err=%v", got, rerr)
	}
}

func TestApplyCloudScope(t *testing.T) {
	t.Parallel()

	t.Run("no cloud leaves multi-cloud", func(t *testing.T) {
		t.Parallel()
		cfg, name := applyCloudScope(CatalogConfig{}) //nolint:exhaustruct // only Cloud under test.
		if name != "azure.json" || cfg.MetadataURLs != nil {
			t.Errorf("got name=%q urls=%v", name, cfg.MetadataURLs)
		}
	})
	t.Run("known cloud narrows MetadataURLs", func(t *testing.T) {
		t.Parallel()
		cfg, name := applyCloudScope(
			CatalogConfig{Cloud: "AzureUSGovernment"},
		) //nolint:exhaustruct // only Cloud under test.
		if name != "azure-AzureUSGovernment.json" {
			t.Errorf("name = %q", name)
		}
		if len(cfg.MetadataURLs) != 1 || cfg.MetadataURLs["AzureUSGovernment"] == "" {
			t.Errorf("MetadataURLs = %v, want narrowed to gov", cfg.MetadataURLs)
		}
	})
	t.Run("explicit MetadataURLs preserved", func(t *testing.T) {
		t.Parallel()
		in := map[string]string{"AzureUSGovernment": "http://test"}
		cfg, name := applyCloudScope(
			CatalogConfig{Cloud: "AzureUSGovernment", MetadataURLs: in}, //nolint:exhaustruct // only fields under test.
		)
		if name != "azure-AzureUSGovernment.json" || cfg.MetadataURLs["AzureUSGovernment"] != "http://test" {
			t.Errorf("got name=%q urls=%v", name, cfg.MetadataURLs)
		}
	})
	t.Run("unknown cloud keeps urls nil", func(t *testing.T) {
		t.Parallel()
		cfg, name := applyCloudScope(
			CatalogConfig{Cloud: "AzureMarsCloud"},
		) //nolint:exhaustruct // only Cloud under test.
		if name != "azure-AzureMarsCloud.json" || cfg.MetadataURLs != nil {
			t.Errorf("got name=%q urls=%v", name, cfg.MetadataURLs)
		}
	})
}

func TestScopedParse(t *testing.T) {
	t.Parallel()

	gov := []byte(`{"clouds":{"AzureUSGovernment":` +
		`{"resourceManager":"management.usgovcloudapi.net","suffixes":{"x":"y"}}},"providers":{}}`)

	t.Run("no cloud is the plain parser", func(t *testing.T) {
		t.Parallel()
		d, err := scopedParse("")(gov)
		if err != nil || d == nil || len(d.Clouds) != 1 {
			t.Errorf("d=%+v err=%v", d, err)
		}
	})
	t.Run("scoped cloud accepts a matching payload", func(t *testing.T) {
		t.Parallel()
		if _, err := scopedParse("AzureUSGovernment")(gov); err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})
	t.Run("scoped cloud rejects a wrong-cloud payload", func(t *testing.T) {
		t.Parallel()
		if _, err := scopedParse("AzureCloud")(gov); !errors.Is(err, ErrCatalogUnavailable) {
			t.Errorf("err = %v, want ErrCatalogUnavailable", err)
		}
	})
	t.Run("scoped cloud propagates a parse error", func(t *testing.T) {
		t.Parallel()
		if _, err := scopedParse("AzureUSGovernment")([]byte("{not json")); err == nil {
			t.Error("want JSON parse error, got nil")
		}
	})
}

func TestWithAPIVersion(t *testing.T) {
	t.Parallel()
	t.Run("set on no-query url", func(t *testing.T) {
		t.Parallel()
		got := withAPIVersion("https://x.com/p", "2022-09-01")
		if got != "https://x.com/p?api-version=2022-09-01" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("overwrite existing and preserve other params", func(t *testing.T) {
		t.Parallel()
		got := withAPIVersion("https://x.com/p?api-version=old&foo=bar", "new")
		if got != "https://x.com/p?api-version=new&foo=bar" { // url.Values.Encode sorts keys: api-version, foo.
			t.Errorf("got %q", got)
		}
	})
	t.Run("parse error passthrough", func(t *testing.T) {
		t.Parallel()
		in := "http://\x7f"
		if got := withAPIVersion(in, "v"); got != in {
			t.Errorf("got %q, want passthrough %q", got, in)
		}
	})
}

func TestProviderOpsURL(t *testing.T) {
	t.Parallel()
	want := "https://management.azure.com/providers/Microsoft.Authorization/providerOperations?api-version=" +
		providerOpsAPIVersion + "&%24expand=resourceTypes"
	for _, base := range []string{"https://management.azure.com", "https://management.azure.com/"} {
		if got := providerOpsURL(base); got != want {
			t.Errorf("providerOpsURL(%q) = %q, want %q", base, got, want)
		}
	}
}

func TestCollectProviderOps(t *testing.T) {
	t.Parallel()
	t.Run("empty value non-nil map", func(t *testing.T) {
		t.Parallel()
		got := collectProviderOps(allProviderOpsResponse{})
		if got == nil || len(got) != 0 {
			t.Errorf("got %v, want non-nil empty", got)
		}
	})
	t.Run("multi keyed by name", func(t *testing.T) {
		t.Parallel()
		raw := `{"value":[
{"name":"Microsoft.Compute","resourceTypes":[
{"name":"virtualMachines","operations":[{"name":"Microsoft.Compute/virtualMachines/read"}]}
]},
{"name":"Microsoft.Storage","resourceTypes":[]}
]}`
		var resp allProviderOpsResponse
		if err := json.Unmarshal([]byte(raw), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got := collectProviderOps(resp)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if _, ok := got["Microsoft.Compute"]; !ok {
			t.Errorf("missing Microsoft.Compute key")
		}
	})
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		got, err := decodeJSON([]byte(`{"value":[{"name":"X"}]}`))
		if err != nil {
			t.Fatalf("decodeJSON: %v", err)
		}
		if len(got.Value) != 1 || got.Value[0].Name != "X" {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("malformed zero value", func(t *testing.T) {
		t.Parallel()
		got, err := decodeJSON([]byte(`{not json`))
		if err == nil {
			t.Fatal("want error")
		}
		if got.Value != nil {
			t.Errorf("got %+v, want zero", got)
		}
	})
}

func TestBuildCatalog(t *testing.T) { //nolint:gocognit // test function with many subtests by design.
	t.Parallel()
	okBody := []byte(`{"resourceManager":"https://management.azure.com/","suffixes":{"x":"y"}}`)
	bg := context.Background()

	t.Run("continue on error, success cloud present", func(t *testing.T) {
		t.Parallel()
		getEndpoints := func(_ context.Context, mURL string) ([]byte, error) {
			if mURL == "bad" {
				return nil, errors.New("unreachable")
			}
			return okBody, nil
		}
		getProviderOps := func(context.Context, string) (map[string]ProviderOps, error) {
			return map[string]ProviderOps{"Microsoft.Compute": {}}, nil
		}
		out, err := buildCatalog(bg, map[string]string{"AzureCloud": "good", "AzureChinaCloud": "bad"},
			getEndpoints, getProviderOps, "https://base")
		if err != nil {
			t.Fatalf("buildCatalog: %v", err)
		}
		if _, ok := out.Clouds["AzureCloud"]; !ok {
			t.Errorf("AzureCloud missing: %+v", out.Clouds)
		}
		if _, ok := out.Clouds["AzureChinaCloud"]; ok {
			t.Errorf("AzureChinaCloud should be absent (fetch errored)")
		}
		if len(out.Providers) != 1 {
			t.Errorf("Providers = %v, want populated", out.Providers)
		}
	})

	t.Run("parse hard-fail bubbles", func(t *testing.T) {
		t.Parallel()
		getEndpoints := func(context.Context, string) ([]byte, error) {
			return []byte(`[{"resourceManager":"https://management.azure.com/"}]`), nil // 2019 array.
		}
		_, err := buildCatalog(bg, map[string]string{"AzureCloud": "x"}, getEndpoints, nil, "https://base")
		if !errors.Is(err, ErrCatalogUnavailable) {
			t.Errorf("err = %v, want ErrCatalogUnavailable", err)
		}
	})

	t.Run("no reachable cloud fail-closed", func(t *testing.T) {
		t.Parallel()
		getEndpoints := func(context.Context, string) ([]byte, error) { return nil, errors.New("down") }
		_, err := buildCatalog(bg, map[string]string{"AzureCloud": "x"}, getEndpoints, nil, "https://base")
		if !errors.Is(err, ErrCatalogUnavailable) ||
			!strings.Contains(err.Error(), "no reachable /metadata/endpoints") {
			t.Errorf("err = %v, want no-reachable ErrCatalogUnavailable", err)
		}
	})

	t.Run("empty baseURL picks providerOpsBase", func(t *testing.T) {
		t.Parallel()
		var gotBase string
		getEndpoints := func(context.Context, string) ([]byte, error) { return okBody, nil }
		getProviderOps := func(_ context.Context, armBase string) (map[string]ProviderOps, error) {
			gotBase = armBase
			return map[string]ProviderOps{}, nil
		}
		if _, err := buildCatalog(bg, map[string]string{"AzureCloud": "x"},
			getEndpoints, getProviderOps, ""); err != nil {
			t.Fatalf("buildCatalog: %v", err)
		}
		if gotBase != "https://management.azure.com" {
			t.Errorf("gotBase = %q, want providerOpsBase output", gotBase)
		}
	})

	t.Run("providerOps soft-fail empties but keeps clouds", func(t *testing.T) {
		t.Parallel()
		getEndpoints := func(context.Context, string) ([]byte, error) { return okBody, nil }
		getProviderOps := func(context.Context, string) (map[string]ProviderOps, error) {
			return nil, errors.New("401")
		}
		// A providerOps fetch failure is soft: no error, an empty (but non-nil)
		// Providers map (Layer-2 stays denied), while Clouds (Layer-3 host pinning)
		// is still populated from the reachable cloud.
		out, err := buildCatalog(bg, map[string]string{"AzureCloud": "x"},
			getEndpoints, getProviderOps, "https://base")
		if err != nil {
			t.Fatalf("buildCatalog: %v", err)
		}
		if out.Providers == nil || len(out.Providers) != 0 {
			t.Errorf("Providers = %v, want empty non-nil", out.Providers)
		}
		if _, ok := out.Clouds["AzureCloud"]; !ok {
			t.Errorf("Clouds = %v, want AzureCloud populated (Layer-3 survives)", out.Clouds)
		}
	})
}

func TestApplyDefaults_FillsZeroValues(t *testing.T) {
	t.Parallel()

	got := applyDefaults(CatalogConfig{}) //nolint:exhaustruct // exercising the defaulting path

	if got.HTTPClient == nil || got.HTTPClient.Timeout != defaultHTTPTimeout {
		t.Errorf("HTTPClient default = %#v, want Timeout %s", got.HTTPClient, defaultHTTPTimeout)
	}
	if got.Clock == nil {
		t.Error("Clock default = nil, want non-nil")
	}
	if len(got.MetadataURLs) != len(defaultMetadataURLs) {
		t.Errorf("MetadataURLs default len = %d, want %d", len(got.MetadataURLs), len(defaultMetadataURLs))
	}
}

func TestApplyDefaults_KeepsSuppliedValues(t *testing.T) {
	t.Parallel()

	client := &http.Client{Timeout: time.Second} //nolint:exhaustruct // test value
	urls := map[string]string{"AzureCloud": "https://example.test"}
	clk := func() time.Time { return time.Unix(0, 0) }

	got := applyDefaults(CatalogConfig{ //nolint:exhaustruct // only the overridden fields matter
		HTTPClient:   client,
		MetadataURLs: urls,
		Config:       cache.Config{Clock: clk}, //nolint:exhaustruct // only Clock matters
	})

	if got.HTTPClient != client {
		t.Error("HTTPClient was overwritten")
	}
	if got.Clock == nil {
		t.Error("Clock was cleared")
	}
	if got.MetadataURLs["AzureCloud"] != "https://example.test" {
		t.Error("MetadataURLs was overwritten")
	}
}

func TestParseCatalogData(t *testing.T) {
	t.Parallel()

	d, err := parseCatalogData([]byte(`{"clouds":{},"providers":{}}`))
	if err != nil {
		t.Fatalf("parseCatalogData valid = %v", err)
	}
	if d == nil || d.Clouds == nil {
		t.Errorf("parseCatalogData = %#v, want non-nil with Clouds", d)
	}

	if _, badErr := parseCatalogData([]byte(`not json`)); badErr == nil {
		t.Error("parseCatalogData(bad) = nil error, want error")
	}
}
