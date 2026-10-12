package azure

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

// gateCheckData is a small real-shaped catalog: Microsoft.Compute with two registered types, their reads and the
// virtual machine start action, and the Microsoft.Resources reads the provider-less routes need.
func gateCheckData() CatalogData {
	return CatalogData{
		Clouds: map[string]CloudEndpoints{"AzureCloud": {ResourceManager: "management.azure.com"}},
		Providers: map[string]ProviderOps{
			"Microsoft.Compute": {
				ResourceTypes: []string{"virtualMachines", "locations"},
				Operations: []ProviderOperation{
					{Name: "Microsoft.Compute/virtualMachines/read"},
					{Name: "Microsoft.Compute/virtualMachines/start/action"},
					{Name: "Microsoft.Compute/locations/read"},
				},
			},
			"Microsoft.Resources": {
				ResourceTypes: []string{"subscriptions", "subscriptions/resourceGroups"},
				Operations: []ProviderOperation{
					{Name: "Microsoft.Resources/subscriptions/read"},
					{Name: "Microsoft.Resources/subscriptions/resourceGroups/read"},
				},
			},
		},
	}
}

// gateCheckSnapshot is a Catalog over gateCheckData whose own fetch fails the test, so a check that reached past
// the snapshot would show.
func gateCheckSnapshot(t *testing.T) Catalog {
	t.Helper()
	data := gateCheckData()
	c := newCatalog(func(context.Context) (CatalogData, error) {
		t.Error("the gate catalog's fetch was called")

		return CatalogData{}, errors.New("unreachable")
	})
	c.peek = func() *CatalogData { return &data }

	return c.PeekSnapshot()
}

func TestStaticShape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want bool
	}{
		{"/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines", true},
		{"/subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}", true},
		{"/subscriptions/{s}/providers/Microsoft.Compute/locations/{location}/virtualMachines", true},
		{"/subscriptions/{subscriptionId}/resourcegroups", true},
		{"/subscriptions/{subscriptionId}/providers/{resourceProviderNamespace}", true},
		{"/providers/{namespace}/operations", false},
		{"/subscriptions/{s}/providers/Microsoft.Compute/{resourceType}/{name}", false},
		{"/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines/{vm}/{child}", false},
		{"/{scope}/providers/Microsoft.Authorization/roleAssignments", true},
		{"/{scope+}/providers/Microsoft.Authorization/roleAssignments", false},
		{"/{roleAssignmentId+}", false},
		{"/subscriptions/{s}/providers/Microsoft.Web/sites/{name}/hybridconnection/{entityName+}", false},
		{"/{tenant}/subscriptions", false},
		{"/subscriptions/{s}/providers/Microsoft.Web/sites/{name}/config{suffix}/web", false},
		{"/subscriptions/{s}/providers/Microsoft.Web/sites/{name}/config/web{suffix}", true},
		{"/subscriptions/{s}/providers/Microsoft.Web/sites/{name}.{slot}", true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := staticShape(tc.path); got != tc.want {
				t.Errorf("staticShape(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestCheckGate_MatchesTheTransportOnAnEscapedPath pins parity with a real request: a fixed path value a/b reaches
// the template as a%2Fb, and the check must classify the same escaped path the transport would send, so it denies
// exactly when Provider.AuthorizeAction's DeriveAction over [http.NewRequest]'s URL denies.
func TestCheckGate_MatchesTheTransportOnAnEscapedPath(t *testing.T) {
	t.Parallel()
	const tpl = "/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines/a%2Fb"
	_, gateErr := checkGate(t.Context(), gateCheckSnapshot(t), http.MethodGet, tpl)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://management.azure.com/subscriptions/x1/providers/Microsoft.Compute/virtualMachines/a%2Fb", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, wireErr := DeriveAction(t.Context(), authreq.NewView(req, ""), gateCheckSnapshot(t))
	if gateErr == nil || wireErr == nil || !errors.Is(gateErr, ErrActionUnresolved) ||
		!errors.Is(wireErr, ErrActionUnresolved) {
		t.Fatalf("check err = %v, wire err = %v; want both denied as non-canonical", gateErr, wireErr)
	}
	// The same reason, not only the same sentinel: a check over the decoded path a/b also denies, as an
	// unregistered trailing segment, which would hide that it classified a different path than the wire carries.
	if gateErr.Error() != wireErr.Error() || !strings.Contains(gateErr.Error(), "non-canonical path") {
		t.Fatalf("check err %q, wire err %q; want the same non-canonical denial", gateErr, wireErr)
	}
}

func TestCheckGate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, method, path string
		checked            bool
		wantErr            error
	}{
		{"admitted read", "GET", "/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines", true, nil},
		{"provider-less read", "GET", "/subscriptions/{subscriptionId}/resourcegroups", true, nil},
		{
			"unregistered type", "GET", "/subscriptions/{s}/providers/Microsoft.Compute/locations/{l}/virtualMachines",
			true, ErrActionUnresolved,
		},
		{
			"namespace not in catalog",
			"GET",
			"/subscriptions/{s}/providers/Microsoft.Nope/things",
			true,
			ErrCatalogUnavailable,
		},
		// A POST admits through the catalog's action, which the same path checked as a GET would deny.
		{
			"admitted action",
			"POST",
			"/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines/{vm}/start",
			true,
			nil,
		},
		{
			"write absent from catalog",
			"PUT",
			"/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines/{vm}",
			true,
			ErrActionUnresolved,
		},
		{"dynamic shape", "GET", "/{scope+}/providers/Microsoft.Authorization/roleAssignments", false, nil},
		{
			"unparsable template",
			"GET",
			"/subscriptions/{s}/providers/Microsoft.Compute/bad%zz",
			true,
			ErrActionUnresolved,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checked, err := checkGate(t.Context(), gateCheckSnapshot(t), tc.method, tc.path)
			if checked != tc.checked {
				t.Fatalf("checked = %v, want %v", checked, tc.checked)
			}
			if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestApplyGateCheck(t *testing.T) {
	t.Parallel()
	ref := func(path string) *apiref.Reference {
		return &apiref.Reference{Method: "GET", PathTemplate: path}
	}

	t.Run("dynamic shape is not checked and never peeks", func(t *testing.T) {
		t.Parallel()
		r := ref("/{scope+}/providers/Microsoft.Authorization/roleAssignments")
		applyGateCheck(t.Context(), func() Catalog {
			t.Error("peeked for a dynamic shape")

			return nil
		}, r)
		if len(r.Gaps) != 0 || len(r.Limitations) != 1 || r.Limitations[0] != gateNotStatic {
			t.Fatalf("gaps %v limitations %v", r.Gaps, r.Limitations)
		}
	})

	t.Run("no catalog in memory", func(t *testing.T) {
		t.Parallel()
		r := ref("/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines")
		applyGateCheck(t.Context(), func() Catalog { return nil }, r)
		if len(r.Gaps) != 0 || len(r.Limitations) != 1 || r.Limitations[0] != gateNotLoaded {
			t.Fatalf("gaps %v limitations %v", r.Gaps, r.Limitations)
		}
	})

	t.Run("admitted path carries only the role limitation", func(t *testing.T) {
		t.Parallel()
		r := ref("/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines")
		applyGateCheck(t.Context(), func() Catalog { return gateCheckSnapshot(t) }, r)
		if len(r.Gaps) != 0 || len(r.Limitations) != 1 || r.Limitations[0] != gateRoleNotChecked {
			t.Fatalf("gaps %v limitations %v", r.Gaps, r.Limitations)
		}
	})
}

func TestApplyGateCheck_Denied(t *testing.T) {
	t.Parallel()
	ref := func(path string) *apiref.Reference {
		return &apiref.Reference{Method: "GET", PathTemplate: path}
	}

	t.Run("denied path gets the gate's reason and nothing else", func(t *testing.T) {
		t.Parallel()
		const path = "/subscriptions/{s}/providers/Microsoft.Compute/locations/{l}/virtualMachines"
		_, err := checkGate(t.Context(), gateCheckSnapshot(t), "GET", path)
		if err == nil {
			t.Fatal("checkGate admitted the unregistered type")
		}
		r := ref(path)
		applyGateCheck(t.Context(), func() Catalog { return gateCheckSnapshot(t) }, r)
		if want := gateDeniesPrefix + err.Error(); len(r.Gaps) != 1 || r.Gaps[0] != want {
			t.Fatalf("gaps %q, want [%q]", r.Gaps, want)
		}
		if strings.Contains(r.Gaps[0], "api_reference") {
			t.Fatalf("gap carries the api_reference pointer: %q", r.Gaps[0])
		}
	})

	t.Run("denied path gets the gap, truncated", func(t *testing.T) {
		t.Parallel()
		r := ref("/subscriptions/{s}/providers/Microsoft.Compute/locations/{l}/" + strings.Repeat("v", 400))
		applyGateCheck(t.Context(), func() Catalog { return gateCheckSnapshot(t) }, r)
		if len(r.Gaps) != 1 || !strings.HasPrefix(r.Gaps[0], gateDeniesPrefix) {
			t.Fatalf("gaps %v", r.Gaps)
		}
		if strings.Contains(r.Gaps[0], "api_reference") {
			t.Fatalf("gap carries the api_reference pointer: %q", r.Gaps[0])
		}
		reason := strings.TrimPrefix(r.Gaps[0], gateDeniesPrefix)
		if n := len([]rune(reason)); n > apiref.MaxGateDetail {
			t.Fatalf("reason is %d runes, want at most %d", n, apiref.MaxGateDetail)
		}
		if len(r.Limitations) != 1 || r.Limitations[0] != gateRoleNotChecked {
			t.Fatalf("limitations %v", r.Limitations)
		}
	})
}

// TestDocsFinish_GateVerdictSetsTheOutcome pins that finish runs the check before it computes the outcome: a denied
// path with no other gap answers incomplete, and an admitted one answers found.
func TestDocsFinish_GateVerdictSetsTheOutcome(t *testing.T) {
	t.Parallel()
	d := NewDocs(specFixture(), "https://management.azure.com", func() Catalog { return gateCheckSnapshot(t) })
	denied := d.finish(t.Context(), &apiref.Reference{
		Method: "GET", PathTemplate: "/subscriptions/{s}/providers/Microsoft.Compute/locations/{l}/virtualMachines",
	})
	if denied.Outcome != apiref.OutcomeIncomplete || len(denied.Reference.Gaps) != 1 ||
		!strings.HasPrefix(denied.Reference.Gaps[0], gateDeniesPrefix) {
		t.Fatalf("denied = %+v", denied)
	}
	admitted := d.finish(t.Context(), &apiref.Reference{
		Method: "GET", PathTemplate: "/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines",
	})
	if admitted.Outcome != apiref.OutcomeFound || len(admitted.Reference.Gaps) != 0 {
		t.Fatalf("admitted = %+v", admitted)
	}
}

// TestApplyGateCheck_MissingNamespace pins that a namespace absent from a loaded catalog is the gate's denial, never
// the not-loaded limitation.
func TestApplyGateCheck_MissingNamespace(t *testing.T) {
	t.Parallel()
	d := NewDocs(specFixture(), "https://management.azure.com", func() Catalog { return gateCheckSnapshot(t) })
	res := d.finish(
		t.Context(),
		&apiref.Reference{Method: "GET", PathTemplate: "/subscriptions/{s}/providers/Microsoft.Nope/things"},
	)
	if res.Outcome != apiref.OutcomeIncomplete || len(res.Reference.Gaps) != 1 ||
		!strings.HasPrefix(res.Reference.Gaps[0], gateDeniesPrefix) ||
		!strings.Contains(res.Reference.Gaps[0], "Microsoft.Nope") {
		t.Fatalf("result %+v gaps %q", res, res.Reference.Gaps)
	}
	if slices.Contains(res.Reference.Limitations, gateNotLoaded) ||
		!slices.Equal(res.Reference.Limitations, []string{gateRoleNotChecked}) {
		t.Fatalf("limitations %q", res.Reference.Limitations)
	}
}
