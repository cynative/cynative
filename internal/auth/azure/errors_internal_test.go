package azure

import (
	"errors"
	"strings"
	"testing"
)

func TestSentinelMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err    error
		prefix string
	}{
		{ErrHostPattern, "azure_hardening: unrecognized host pattern"},
		{ErrHostClaimMismatch, "azure_hardening: host does not match azure_auth claim"},
		{ErrCatalogUnavailable, "azure_hardening: endpoint/provider-operations catalog unavailable"},
		{ErrActionUnresolved, "azure_hardening: cannot resolve required RBAC action"},
		{ErrActionAmbiguous, "azure_hardening: ambiguous action (catalog has read and action for one path)"},
		{ErrActionDenied, "azure_hardening: action not allowed by role definition"},
		{ErrDataPlaneNotSupported, "azure_hardening: data-plane operations out of scope (control-plane only)"},
		{ErrGraphNotSupported, "azure_hardening: Microsoft Graph is not Azure-RBAC-gated"},
		{ErrTenantUnresolved, "azure_hardening: target tenant could not be resolved"},
		{ErrRoleFetchFailed, "azure_hardening: role definition fetch failed"},
		{ErrModelSuppliedCredential, "azure_hardening: model-supplied credential (SAS) rejected"},
	}
	for _, c := range cases {
		if c.err == nil || !strings.HasPrefix(c.err.Error(), c.prefix) {
			t.Errorf("sentinel %v does not start with %q", c.err, c.prefix)
		}
		// Wrapping must remain errors.Is-recoverable.
		wrapped := errors.Join(c.err)
		if !errors.Is(wrapped, c.err) {
			t.Errorf("errors.Is failed for %q", c.prefix)
		}
	}
}
