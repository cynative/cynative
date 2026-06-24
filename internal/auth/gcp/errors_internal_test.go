package gcp

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
		{ErrHostPattern, "gcp_hardening: unrecognized host pattern"},
		{ErrHostClaimMismatch, "gcp_hardening: host does not match gcp_auth claim"},
		{ErrCatalogUnavailable, "gcp_hardening: API discovery catalog unavailable"},
		{ErrClassifierUnknownOp, "gcp_hardening: cannot identify method from request"},
		{ErrPermissionUnresolved, "gcp_hardening: cannot resolve required permission"},
		{ErrPermissionDenied, "gcp_hardening: permission not in allow-list role(s)"},
		{ErrRoleFetchFailed, "gcp_hardening: allow-list role fetch failed"},
		{ErrRoleDisabled, "gcp_hardening: allow-list role is disabled or deleted"},
		{ErrInvalidRoleRef, "gcp_hardening: invalid role reference"},
		{ErrProjectUnresolved, "gcp_hardening: caller project ID could not be resolved"},
	}
	for _, c := range cases {
		if c.err == nil || !strings.HasPrefix(c.err.Error(), c.prefix) {
			t.Errorf("sentinel %v does not start with %q", c.err, c.prefix)
		}
		// Wrapping with %w must remain errors.Is-recoverable.
		wrapped := errors.Join(c.err)
		if !errors.Is(wrapped, c.err) {
			t.Errorf("errors.Is failed for %q", c.prefix)
		}
	}
}
