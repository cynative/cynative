package azure

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// classifierFakeCatalog is a hand-written Catalog fake for the pure classifier tests.
// It is keyed off lowercased (namespace, resourceTypePath) so case-insensitive
// matching can be exercised without stemming. resTypes lists the registered
// resource-type paths per namespace; verbs maps a (ns|typePath|token) key to the
// distinct registered verbs (for ambiguity-deny) and their isDataAction flags.
type classifierFakeCatalog struct {
	resTypes map[string][]string
	verbs    map[string][]string
	isData   map[string]bool
}

func (f classifierFakeCatalog) ResolveCloud(_ context.Context, p ParsedHost) (ParsedHost, error) {
	return p, nil
}

func (f classifierFakeCatalog) ResourceTypes(_ context.Context, namespace string) ([]string, error) {
	if rt, ok := f.resTypes[namespace]; ok {
		return rt, nil
	}
	return nil, nil
}

func (f classifierFakeCatalog) LookupOperation(
	_ context.Context, namespace, resourceTypePath, verbToken string,
) ([]string, map[string]bool, error) {
	key := namespace + "|" + resourceTypePath + "|" + verbToken
	verbs := f.verbs[key]
	byVerb := map[string]bool{}
	for _, v := range verbs {
		byVerb[v] = f.isData[namespace+"|"+resourceTypePath+"/"+v]
	}
	return verbs, byVerb, nil
}

func classifierCatalog() classifierFakeCatalog {
	return classifierFakeCatalog{
		resTypes: map[string][]string{
			"Microsoft.Compute": {
				"virtualMachines", "virtualMachines/extensions", "virtualMachines/runCommands",
			},
			"Microsoft.Storage":       {"storageAccounts"},
			"Microsoft.DocumentDB":    {"databaseAccounts"},
			"Microsoft.ResourceGraph": {"resources"},
			"Microsoft.OperationalInsights": {
				"workspaces", "workspaces/providers/Microsoft.SecurityInsights/incidents",
			},
			"Microsoft.SecurityInsights": {"incidents"},
		},
		verbs: map[string][]string{
			// Cosmos readonlykeys dual: catalog registers BOTH /read and /action.
			"Microsoft.DocumentDB|databaseAccounts|readonlykeys": {"read", "action"},
			// listKeys is a single /action verb (no /read).
			"Microsoft.Storage|storageAccounts|listKeys": {"action"},
			// runCommand instance-action (singular) is a single /action verb.
			"Microsoft.Compute|virtualMachines|runCommand": {"action"},
		},
		isData: map[string]bool{
			// listKeys is isDataAction=FALSE yet exfiltrates data — safety keys off the
			// structural /action verb, not this flag.
			"Microsoft.Storage|storageAccounts/action": false,
		},
	}
}

func creq(t *testing.T, method, rawurl string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return &http.Request{Method: method, URL: u, Header: http.Header{}}
}

func TestDeriveAction(t *testing.T) {
	t.Parallel()

	cat := classifierCatalog()
	tests := []struct {
		name     string
		req      *http.Request
		wantFull string
		wantErr  error
	}{
		{
			name: "GET get → read",
			req: creq(
				t,
				"GET",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm?api-version=2023-03-01",
			),
			wantFull: "Microsoft.Compute/virtualMachines/read",
		},
		{
			name: "GET list → read (shared with get)",
			req: creq(
				t,
				"GET",
				"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines",
			),
			wantFull: "Microsoft.Compute/virtualMachines/read",
		},
		{
			name: "PUT → write",
			req: creq(
				t,
				"PUT",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			),
			wantFull: "Microsoft.Compute/virtualMachines/write",
		},
		{
			name: "PATCH → write",
			req: creq(
				t,
				"PATCH",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			),
			wantFull: "Microsoft.Compute/virtualMachines/write",
		},
		{
			name: "DELETE → delete",
			req: creq(
				t,
				"DELETE",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			),
			wantFull: "Microsoft.Compute/virtualMachines/delete",
		},
		{
			name: "POST instance action → action",
			req: creq(
				t,
				"POST",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/runCommand",
			),
			wantFull: "Microsoft.Compute/virtualMachines/runCommand/action",
		},
		{
			name: "Storage listKeys POST → /action (NOT /read), isDataAction irrelevant",
			req: creq(
				t,
				"POST",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/listKeys",
			),
			wantFull: "Microsoft.Storage/storageAccounts/listKeys/action",
		},
		{
			name:     "ResourceGraph POST-read → resources/read (allow-list)",
			req:      creq(t, "POST", "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"),
			wantFull: "Microsoft.ResourceGraph/resources/read",
		},
		{
			name: "nested /providers/ namespace shift → last /providers/ wins",
			req: creq(
				t,
				"GET",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w/providers/Microsoft.SecurityInsights/incidents/i",
			),
			wantFull: "Microsoft.SecurityInsights/incidents/read",
		},
		{
			name:     "provider-less subscriptions root → Microsoft.Resources read",
			req:      creq(t, "GET", "https://management.azure.com/subscriptions"),
			wantFull: "Microsoft.Resources/subscriptions/read",
		},
		{
			name: "GET async poll shape → scope-level read",
			req: creq(
				t,
				"GET",
				"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/locations/eastus/operations/op123",
			),
			wantFull: "Microsoft.Compute/operations/read",
		},
		{
			name: "Cosmos readonlykeys POST dual → ambiguity DENY",
			req: creq(
				t,
				"POST",
				"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/a/readonlykeys",
			),
			wantErr: ErrActionAmbiguous,
		},
		{
			name: "unknown resource type → unresolved",
			req: creq(
				t,
				"GET",
				"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/widgets/w",
			),
			wantErr: ErrActionUnresolved,
		},
		{
			name: "GET unregistered segment trailing a known type → unresolved",
			req: creq(
				t,
				"GET",
				"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/vm/bogus/x",
			),
			wantErr: ErrActionUnresolved,
		},
		{
			name: "POST two unregistered trailing segments → unresolved",
			req: creq(
				t,
				"POST",
				"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/vm/bogus/b/doThing",
			),
			wantErr: ErrActionUnresolved,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := DeriveAction(context.Background(), tc.req, cat)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("DeriveAction err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DeriveAction: %v", err)
			}
			if got.Full != tc.wantFull {
				t.Errorf("DeriveAction Full = %q, want %q", got.Full, tc.wantFull)
			}
		})
	}
}

// TestDeriveActionRunCommandVsRunCommands pins the one-char trap: runCommand
// (instance action) vs runCommands (child resource type GET).
func TestDeriveActionRunCommandVsRunCommands(t *testing.T) {
	t.Parallel()

	cat := classifierCatalog()

	action, err := DeriveAction(context.Background(), creq(
		t,
		"POST",
		"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/runCommand",
	), cat)
	if err != nil || action.Full != "Microsoft.Compute/virtualMachines/runCommand/action" {
		t.Fatalf("runCommand action = %q err=%v", action.Full, err)
	}

	child, err := DeriveAction(context.Background(), creq(
		t,
		"GET",
		"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/runCommands/rc",
	), cat)
	if err != nil || child.Full != "Microsoft.Compute/virtualMachines/runCommands/read" {
		t.Fatalf("runCommands child read = %q err=%v", child.Full, err)
	}
}

// TestDeriveActionCoverageGaps exercises the branches that the table-driven test
// does not reach, ensuring 100% statement coverage on classifier.go.
func TestDeriveActionCoverageGaps(t *testing.T) {
	t.Parallel()
	cat := classifierCatalog()
	ctx := context.Background()

	// providerLessAction: POST on a provider-less path → ErrActionUnresolved (line 82).
	_, err := DeriveAction(ctx, creq(t, "POST", "https://management.azure.com/subscriptions"), cat)
	if !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("provider-less POST: want ErrActionUnresolved, got %v", err)
	}

	// providerLessAction: bare /managementGroups is NOT a real ARM route (real
	// route is provider-ful /providers/Microsoft.Management/managementGroups), so
	// it now fails closed. Do NOT re-add a managementgroups branch.
	_, mgErr := DeriveAction(ctx, creq(t, "GET", "https://management.azure.com/managementGroups"), cat)
	if !errors.Is(mgErr, ErrActionUnresolved) {
		t.Errorf("bare managementGroups: want ErrActionUnresolved, got %v", mgErr)
	}

	// providerLessAction: unknown root → ErrActionUnresolved (line 91).
	_, err = DeriveAction(ctx, creq(t, "GET", "https://management.azure.com/unknown"), cat)
	if !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("provider-less unknown root: want ErrActionUnresolved, got %v", err)
	}

	// resolveResourceType catalog error path (line 121): catalog returns error for ResourceTypes.
	errCat := classifierFakeCatalog{
		resTypes: nil, // all namespaces absent → nil slice returned, no error
		verbs:    nil,
		isData:   nil,
	}
	// Use a catalog that injects an error via a wrapper that implements Catalog.
	catErr := errFetchCatalog{}
	_, err = DeriveAction(ctx, creq(t, "GET",
		"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/vm"), catErr)
	if !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("ResourceTypes fetch error: want ErrCatalogUnavailable, got %v", err)
	}
	_ = errCat // used above to document intent; errFetchCatalog is the real injector.

	// verbAction unsupported method (line 168).
	_, err = DeriveAction(ctx, creq(t, "HEAD",
		"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/vm"), cat)
	if !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("HEAD method: want ErrActionUnresolved, got %v", err)
	}

	// postAction catalog lookup error (line 177): ResourceTypes must succeed (so
	// resolveResourceType finds the type) but LookupOperation fails.
	catLookupErr := lookupErrCatalog{}
	_, err = DeriveAction(ctx, creq(
		t,
		"POST",
		"https://management.azure.com/subscriptions/s/providers/Microsoft.Storage/storageAccounts/a/listKeys",
	), catLookupErr)
	if !errors.Is(err, ErrCatalogUnavailable) {
		t.Errorf("postAction lookup error: want ErrCatalogUnavailable, got %v", err)
	}

	// splitPath empty path (line 211): provider-less root with empty path → segs nil → len==0.
	_, err = DeriveAction(ctx, creq(t, "GET", "https://management.azure.com/"), cat)
	if !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("empty path: want ErrActionUnresolved, got %v", err)
	}

	// distinct duplicate-skip branch (line 223): exercised indirectly; call directly.
	d := distinct([]string{"read", "READ", "action"})
	if len(d) != 2 {
		t.Errorf("distinct dedup: got %v, want 2 elements", d)
	}
}

// lookupErrCatalog succeeds on ResourceTypes (so resolveResourceType can match
// a type) but fails on LookupOperation, exercising the postAction error path.
type lookupErrCatalog struct{}

func (lookupErrCatalog) ResolveCloud(_ context.Context, p ParsedHost) (ParsedHost, error) {
	return p, nil
}

func (lookupErrCatalog) ResourceTypes(_ context.Context, _ string) ([]string, error) {
	return []string{"storageAccounts"}, nil
}

func (lookupErrCatalog) LookupOperation(
	_ context.Context, _, _, _ string,
) ([]string, map[string]bool, error) {
	return nil, nil, ErrCatalogUnavailable
}

func TestDeriveAction_emptySegmentRejected(t *testing.T) {
	t.Parallel()
	cat := classifierCatalog()
	ctx := context.Background()
	cases := []string{
		// Interior // skews parity: would move "operations" to an even slot.
		"https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines//operations",
		// Empty segment before the type-walk in resolveResourceType.
		"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines//extensions/e",
		// Empty segment in a provider-less path.
		"https://management.azure.com/subscriptions//resourceGroups",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			if _, err := DeriveAction(ctx, creq(t, "GET", u), cat); !errors.Is(err, ErrActionUnresolved) {
				t.Errorf("empty segment %q: want ErrActionUnresolved, got %v", u, err)
			}
		})
	}
}

func TestDeriveAction_nonCanonicalPathRejected(t *testing.T) {
	t.Parallel()
	cat := classifierCatalog()
	ctx := context.Background()
	cases := []struct {
		name, url string
	}{
		{"dot segment in id slot", "https://management.azure.com/subscriptions/./resourceGroups"},
		{"dot-dot segment", "https://management.azure.com/subscriptions/s/../resourceGroups"},
		{
			"dot segment as type position",
			"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/./virtualMachines/vm",
		},
		{"percent-encoded slash", "https://management.azure.com/subscriptions/s%2fresourceGroups"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DeriveAction(ctx, creq(t, "GET", c.url), cat); !errors.Is(err, ErrActionUnresolved) {
				t.Errorf("%s (%s): want ErrActionUnresolved, got %v", c.name, c.url, err)
			}
		})
	}
}

// errFetchCatalog is a Catalog implementation whose ResourceTypes and
// LookupOperation always return ErrCatalogUnavailable, to exercise error paths.
type errFetchCatalog struct{}

func (errFetchCatalog) ResolveCloud(_ context.Context, p ParsedHost) (ParsedHost, error) {
	return p, nil
}

func (errFetchCatalog) ResourceTypes(_ context.Context, _ string) ([]string, error) {
	return nil, ErrCatalogUnavailable
}

func (errFetchCatalog) LookupOperation(
	_ context.Context, _, _, _ string,
) ([]string, map[string]bool, error) {
	return nil, nil, ErrCatalogUnavailable
}

func TestProviderLessAction_routeTable(t *testing.T) {
	t.Parallel()
	cat := classifierCatalog()
	ctx := context.Background()
	cases := []struct {
		url      string
		wantFull string
	}{
		{"https://management.azure.com/subscriptions", "Microsoft.Resources/subscriptions/read"},
		{"https://management.azure.com/subscriptions/s", "Microsoft.Resources/subscriptions/read"},
		{
			"https://management.azure.com/subscriptions/s/resourcegroups",
			"Microsoft.Resources/subscriptions/resourceGroups/read",
		},
		{
			"https://management.azure.com/subscriptions/s/resourceGroups/rg",
			"Microsoft.Resources/subscriptions/resourceGroups/read",
		},
		{"https://management.azure.com/subscriptions/s/locations", "Microsoft.Resources/subscriptions/locations/read"},
		{"https://management.azure.com/subscriptions/s/providers", "Microsoft.Resources/subscriptions/providers/read"},
		{"https://management.azure.com/subscriptions/s/tagNames", "Microsoft.Resources/subscriptions/tagNames/read"},
		{"https://management.azure.com/subscriptions/s/resources", "Microsoft.Resources/subscriptions/resources/read"},
		{
			"https://management.azure.com/subscriptions/s/resourceGroups/rg/resources",
			"Microsoft.Resources/subscriptions/resourceGroups/resources/read",
		},
		{"https://management.azure.com/tenants", "Microsoft.Resources/tenants/read"},
		{"https://management.azure.com/providers", "Microsoft.Resources/providers/read"},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			t.Parallel()
			got, err := DeriveAction(ctx, creq(t, "GET", c.url), cat)
			if err != nil || got.Full != c.wantFull {
				t.Errorf("derive %s: got %q err=%v, want %q", c.url, got.Full, err, c.wantFull)
			}
		})
	}
}

func TestProviderLessAction_failsClosed(t *testing.T) {
	t.Parallel()
	cat := classifierCatalog()
	ctx := context.Background()
	cases := []struct {
		name, method, url string
	}{
		{"trailing unconsumed segment", "GET", "https://management.azure.com/subscriptions/s/resourceGroups/rg/extra"},
		{"unknown root", "GET", "https://management.azure.com/widgets"},
		{"bare resourcegroups (not a real route)", "GET", "https://management.azure.com/resourcegroups"},
		{"bare locations (not a real route)", "GET", "https://management.azure.com/locations"},
		{"non-GET method", "POST", "https://management.azure.com/subscriptions/s/resourceGroups"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DeriveAction(ctx, creq(t, c.method, c.url), cat); !errors.Is(err, ErrActionUnresolved) {
				t.Errorf("%s: want ErrActionUnresolved, got %v", c.name, err)
			}
		})
	}
}

// resourcesValidateCatalog answers ValidateAction's (lowercased) LookupOperation
// for the provider-less Microsoft.Resources reads. providerLessAction is pure, so
// only ValidateAction touches the catalog on this path.
type resourcesValidateCatalog struct{}

func (resourcesValidateCatalog) ResolveCloud(_ context.Context, p ParsedHost) (ParsedHost, error) {
	return p, nil
}

func (resourcesValidateCatalog) ResourceTypes(context.Context, string) ([]string, error) {
	return nil, nil
}

func (resourcesValidateCatalog) LookupOperation(
	_ context.Context, ns, typePath, token string,
) ([]string, map[string]bool, error) {
	known := map[string]bool{
		"microsoft.resources|subscriptions|read":                          true,
		"microsoft.resources|subscriptions/resourcegroups|read":           true,
		"microsoft.resources|subscriptions/locations|read":                true,
		"microsoft.resources|subscriptions/providers|read":                true,
		"microsoft.resources|subscriptions/tagnames|read":                 true,
		"microsoft.resources|subscriptions/resources|read":                true,
		"microsoft.resources|subscriptions/resourcegroups/resources|read": true,
		"microsoft.resources|tenants|read":                                true,
		"microsoft.resources|providers|read":                              true,
	}
	if known[ns+"|"+typePath+"|"+token] {
		return []string{token}, map[string]bool{token: false}, nil
	}
	return nil, map[string]bool{}, nil
}

func TestPollAction_positionalShapes(t *testing.T) {
	t.Parallel()
	cat := classifierCatalog()
	ctx := context.Background()
	cases := []struct {
		name, url, wantFull string
		wantErr             bool // true → must NOT classify as a poll (falls through, fails closed here).
	}{
		{
			name:     "VM named operations is a resource name, not a poll",
			url:      "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/operations",
			wantFull: "Microsoft.Compute/virtualMachines/read",
		},
		{
			name:     "namespace-root bare operations list",
			url:      "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/operations",
			wantFull: "Microsoft.Compute/operations/read",
		},
		{
			name:     "namespace-root operations poll with id",
			url:      "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/operations/op1",
			wantFull: "Microsoft.Compute/operations/read",
		},
		{
			name:     "location-scoped operations poll",
			url:      "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/locations/eastus/operations/op1",
			wantFull: "Microsoft.Compute/operations/read",
		},
		{
			name:     "resource-scoped operationStatuses poll",
			url:      "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/operationStatuses/op1",
			wantFull: "Microsoft.Compute/operationstatuses/read",
		},
		{
			name: "even marker with >1 trailing segments is not a poll",
			// rest=[virtualMachines, vm, operations, extra, more]: "operations" at
			// even index 2 but with two trailing segments → isPollShape false → falls
			// through → fails closed.
			url:     "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/vm/operations/extra/more",
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := DeriveAction(ctx, creq(t, "GET", c.url), cat)
			if c.wantErr {
				if !errors.Is(err, ErrActionUnresolved) {
					t.Errorf("%s: want ErrActionUnresolved, got %q err=%v", c.name, got.Full, err)
				}
				return
			}
			if err != nil || got.Full != c.wantFull {
				t.Errorf("%s: got %q err=%v, want %q", c.name, got.Full, err, c.wantFull)
			}
		})
	}
}

func TestPollAction_bareMarkerAtInstancePositionFallsThrough(t *testing.T) {
	t.Parallel()
	cat := classifierCatalog()
	ctx := context.Background()
	// rest = [virtualMachines, vm, operations]: marker even at i=2 but BARE (no id)
	// and not the namespace root → must fall through to resolveResourceType. The
	// catalog has no virtualMachines/operations type, so it fails closed.
	u := "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/vm/operations"
	if _, err := DeriveAction(ctx, creq(t, "GET", u), cat); !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("bare marker at instance position: want ErrActionUnresolved (not a poll), got %v", err)
	}
}

func TestProviderLessAction_emittedActionsValidateAgainstCatalog(t *testing.T) {
	t.Parallel()
	cat := resourcesValidateCatalog{}
	ctx := context.Background()
	// Every multi-segment provider-less row: assert the derived Action.Full (red
	// against the current segs[0] code, which emits subscriptions/read) AND that it
	// validates against a catalog seeded with the exact operation names.
	cases := []struct {
		url, wantFull string
	}{
		{
			"https://management.azure.com/subscriptions/s/resourcegroups",
			"Microsoft.Resources/subscriptions/resourceGroups/read",
		},
		{"https://management.azure.com/subscriptions/s/locations", "Microsoft.Resources/subscriptions/locations/read"},
		{"https://management.azure.com/subscriptions/s/providers", "Microsoft.Resources/subscriptions/providers/read"},
		{"https://management.azure.com/subscriptions/s/tagNames", "Microsoft.Resources/subscriptions/tagNames/read"},
		{"https://management.azure.com/subscriptions/s/resources", "Microsoft.Resources/subscriptions/resources/read"},
		{
			"https://management.azure.com/subscriptions/s/resourceGroups/rg/resources",
			"Microsoft.Resources/subscriptions/resourceGroups/resources/read",
		},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			t.Parallel()
			a, err := DeriveAction(ctx, creq(t, "GET", c.url), cat)
			if err != nil || a.Full != c.wantFull {
				t.Fatalf("derive %s: got %q err=%v, want %q", c.url, a.Full, err, c.wantFull)
			}
			if verr := ValidateAction(ctx, cat, a); verr != nil {
				t.Errorf("validate %s (%s): %v — emitted action absent from catalog", c.url, a.Full, verr)
			}
		})
	}
}
