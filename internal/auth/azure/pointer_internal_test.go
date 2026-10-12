package azure

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

func TestReferencePointer(t *testing.T) {
	t.Parallel()
	got := referencePointer("Microsoft.Compute")
	want := `For an operation's request template call api_reference with ` +
		`{"connector":"azure","operation":"<OperationId>","service":"Microsoft.Compute"}.`
	if got != want {
		t.Fatalf("referencePointer = %q, want %q", got, want)
	}
}

func TestReferencePointerBoundsAndEscapesTheNamespace(t *testing.T) {
	t.Parallel()
	for _, ns := range []string{
		strings.Repeat("Microsoft.Compute", 100),
		`"}],"x":"<script> ` + strings.Repeat(`\"`, 300),
	} {
		got := referencePointer(ns)
		const head = "For an operation's request template call api_reference with "
		if !strings.HasPrefix(got, head) || !strings.HasSuffix(got, "}.") {
			t.Fatalf("pointer lost its frame: %q", got)
		}
		var lookup map[string]string
		if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(got, head), ".")), &lookup); err != nil {
			t.Fatalf("pointer JSON does not parse: %v: %q", err, got)
		}
		if lookup["connector"] != "azure" || lookup["operation"] != "<OperationId>" || len(lookup) != 3 {
			t.Fatalf("pointer keys = %v", lookup)
		}
		if n := len([]rune(lookup["service"])); n > apiref.MaxChoice {
			t.Fatalf("service echo is %d runes, want at most %d", n, apiref.MaxChoice)
		}
	}
}

func TestAuthorizeActionAppendsThePointerToStructuralMisses(t *testing.T) {
	t.Parallel()
	p := buildProvider(t) // providerCatalog: lower-cased lookups, so ValidateAction and the role run.
	cases := []struct {
		name, method, url, service, namespace string
	}{
		{
			"resource type miss", "GET",
			"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachinez/vm",
			"Microsoft.Compute", "Microsoft.Compute",
		},
		{
			"unregistered trailing segment", "GET",
			"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/vm/bogus/x",
			"Microsoft.Compute", "Microsoft.Compute",
		},
		{
			"provider-less route miss", "GET",
			"https://management.azure.com/subscriptions/s/resourceGroupz",
			"Microsoft.Resources", "Microsoft.Resources",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := p.AuthorizeAction(t.Context(), providerView(t, tc.method, tc.url), azArgs(t, tc.service))
			if !errors.Is(err, ErrActionUnresolved) {
				t.Fatalf("err = %v, want ErrActionUnresolved", err)
			}
			if !strings.HasSuffix(err.Error(), ". "+referencePointer(tc.namespace)) {
				t.Fatalf("err = %q, want it to end with the pointer for %s", err, tc.namespace)
			}
			if !strings.HasPrefix(err.Error(), ErrActionUnresolved.Error()) {
				t.Fatalf("err = %q, want the gate text first", err)
			}
		})
	}
}

func TestAuthorizeActionLeavesOtherDenialsAlone(t *testing.T) {
	t.Parallel()
	p := buildProvider(t) // providerCatalog: lower-cased lookups, so ValidateAction and the role run.
	cases := []struct {
		name, method, url, service string
		want                       error
	}{
		{
			"non-canonical path", "GET",
			"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines/a%2Fb",
			"Microsoft.Compute", ErrActionUnresolved,
		},
		{
			"provider-less non-GET", "POST",
			"https://management.azure.com/subscriptions/s",
			"Microsoft.Resources", ErrActionUnresolved,
		},
		{
			"unsupported method", "HEAD",
			"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines",
			"Microsoft.Compute", ErrActionUnresolved,
		},
		{
			"role denial", "POST",
			"https://management.azure.com/subscriptions/s/providers/Microsoft.Storage/storageAccounts/a/listKeys",
			"Microsoft.Storage", ErrActionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := p.AuthorizeAction(t.Context(), providerView(t, tc.method, tc.url), azArgs(t, tc.service))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "api_reference") {
				t.Fatalf("err = %q, want no pointer", err)
			}
		})
	}
}

func TestValidateActionAbsentTextHasNoPointer(t *testing.T) {
	t.Parallel()
	err := ValidateAction(t.Context(), classifierCatalog(), mk("Microsoft.Compute", "virtualMachines", "read"))
	if !errors.Is(err, ErrActionUnresolved) || strings.Contains(err.Error(), "api_reference") {
		t.Fatalf("err = %v", err)
	}
}

func TestWithReferencePointerPassesOtherErrorsThrough(t *testing.T) {
	t.Parallel()
	if withReferencePointer(nil) != nil {
		t.Fatal("nil error changed")
	}
	plain := errors.New("plain")
	got := withReferencePointer(plain)
	if !errors.Is(got, plain) || got.Error() != plain.Error() {
		t.Fatalf("plain error changed: %v", got)
	}
	miss := &structuralMissError{namespace: "Microsoft.Compute", err: ErrActionUnresolved}
	if miss.Error() != ErrActionUnresolved.Error() || !errors.Is(miss, ErrActionUnresolved) {
		t.Fatalf("structuralMissError = %q", miss)
	}
}
