package azure

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// providerFakeCatalog wires both ResourceTypes (for derivation) and
// LookupOperation (for ambiguity + validation) for the end-to-end provider tests.
// Keys in verbs and data are always stored and compared case-insensitively so that
// the fake serves both DeriveAction (mixed-case namespace from URL) and
// ValidateAction (lowercased before the catalog call) without duplication.
type providerFakeCatalog struct {
	// resTypes maps original-case namespace → resource type paths (DeriveAction
	// passes the URL segment as-is; the fake does a case-insensitive lookup).
	resTypes map[string][]string
	// verbs maps lowercase "ns|typePath|verbToken" → list of distinct verbs.
	verbs map[string][]string
	// data maps lowercase "ns/typePath/verb" → isDataAction.
	data map[string]bool
}

func (f providerFakeCatalog) ResolveCloud(_ context.Context, p ParsedHost) (ParsedHost, error) {
	return p, nil
}

func (f providerFakeCatalog) ResourceTypes(_ context.Context, namespace string) ([]string, error) {
	for k, v := range f.resTypes {
		if strings.EqualFold(k, namespace) {
			return v, nil
		}
	}
	return nil, nil
}

func (f providerFakeCatalog) LookupOperation(
	_ context.Context, namespace, resourceTypePath, verbToken string,
) ([]string, map[string]bool, error) {
	key := strings.ToLower(namespace + "|" + resourceTypePath + "|" + verbToken)
	verbs := f.verbs[key]
	byVerb := map[string]bool{}
	for _, v := range verbs {
		byVerb[v] = f.data[strings.ToLower(namespace+"/"+resourceTypePath+"/"+v)]
	}
	return verbs, byVerb, nil
}

func providerCatalog() providerFakeCatalog {
	return providerFakeCatalog{
		resTypes: map[string][]string{
			"Microsoft.Compute":       {"virtualMachines"},
			"Microsoft.Storage":       {"storageAccounts"},
			"Microsoft.DocumentDB":    {"databaseAccounts"},
			"Microsoft.ResourceGraph": {"resources"},
		},
		// Keys are lowercase "ns|typePath|verbToken".
		// DeriveAction's postAction calls LookupOperation with the URL-derived
		// namespace; ValidateAction calls it with the fully lowercased action.
		verbs: map[string][]string{
			// DeriveAction: GET → no LookupOperation call; ValidateAction lookup.
			"microsoft.compute|virtualmachines|read": {"read"},
			"microsoft.resourcegraph|resources|read": {"read"},
			// DeriveAction postAction for listKeys → single "action" verb → no ambiguity.
			"microsoft.storage|storageaccounts|listkeys": {"action"},
			// ValidateAction for listKeys/action: lowercases a.Verb → "listkeys/action";
			// byVerb must be keyed by that same token so the exists-check passes.
			"microsoft.storage|storageaccounts|listkeys/action": {"listkeys/action"},
			// DeriveAction postAction for readonlykeys → two verbs → ErrActionAmbiguous.
			"microsoft.documentdb|databaseaccounts|readonlykeys": {"read", "action"},
		},
	}
}

func buildProvider(t *testing.T) *Provider {
	t.Helper()

	cat := providerCatalog()
	eval := NewRoleEvaluator(RolePermissions{Actions: []string{"*/read"}}) // Reader.
	return NewProvider(cat, eval, "Reader")
}

func azArgs(t *testing.T, service string) json.RawMessage {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"azure_auth": map[string]string{"service": service}})
	return b
}

func areq(t *testing.T, method, rawurl string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return (&http.Request{Method: method, URL: u, Header: http.Header{}}).WithContext(context.Background())
}

func TestProviderAuthorizeAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		url     string
		service string
		wantErr error // nil means allowed.
	}{
		{
			name:    "H1 list VMs allowed under Reader",
			method:  "GET",
			url:     "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines",
			service: "Microsoft.Compute",
		},
		{
			name:    "H6 ResourceGraph POST-read allowed under Reader",
			method:  "POST",
			url:     "https://management.azure.com/providers/Microsoft.ResourceGraph/resources",
			service: "Microsoft.ResourceGraph",
		},
		{
			name:    "S4 listKeys POST denied under Reader (/action)",
			method:  "POST",
			url:     "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/listKeys",
			service: "Microsoft.Storage",
			wantErr: ErrActionDenied,
		},
		{
			name:    "A9 Cosmos readonlykeys POST dual → ambiguity DENY",
			method:  "POST",
			url:     "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/a/readonlykeys",
			service: "Microsoft.DocumentDB",
			wantErr: ErrActionAmbiguous,
		},
		{
			name:    "claim lie: service mismatch denied",
			method:  "GET",
			url:     "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines",
			service: "Microsoft.KeyVault",
			wantErr: ErrHostClaimMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := buildProvider(t)
			err := p.AuthorizeAction(context.Background(), areq(t, tc.method, tc.url), azArgs(t, tc.service))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("AuthorizeAction err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("AuthorizeAction allowed case errored: %v", err)
			}
		})
	}
}

func TestProviderMissingAzureAuth(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)
	if err := p.AuthorizeAction(context.Background(),
		areq(t, "GET", "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines"),
		json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing azure_auth must error")
	}
}

func TestProviderInvalidJSON(t *testing.T) {
	t.Parallel()

	p := buildProvider(t)
	err := p.AuthorizeAction(context.Background(),
		areq(t, "GET", "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines"),
		json.RawMessage(`not-json`))
	if err == nil {
		t.Fatal("invalid JSON must error")
	}
}

// providerValidateCatalog returns an action from DeriveAction but then reports it
// absent from the catalog in LookupOperation (ValidateAction error path).
type providerValidateCatalog struct{ providerFakeCatalog }

func (providerValidateCatalog) LookupOperation(
	_ context.Context, _, _, _ string,
) ([]string, map[string]bool, error) {
	// Return no verbs — ValidateAction will see the token absent and error.
	return nil, map[string]bool{}, nil
}

func TestProviderValidateActionError(t *testing.T) {
	t.Parallel()

	base := providerCatalog()
	cat := providerValidateCatalog{base}
	eval := NewRoleEvaluator(RolePermissions{Actions: []string{"*/read"}})
	p := NewProvider(cat, eval, "Reader")

	err := p.AuthorizeAction(context.Background(),
		areq(t, "GET", "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines"),
		azArgs(t, "Microsoft.Compute"))
	if !errors.Is(err, ErrActionUnresolved) {
		t.Fatalf("expected ErrActionUnresolved, got %v", err)
	}
}
