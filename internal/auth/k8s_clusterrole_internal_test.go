package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestClusterRolePath(t *testing.T) {
	t.Parallel()

	const base = "/apis/rbac.authorization.k8s.io/v1/clusterroles/"
	tests := []struct {
		name string
		role string
		want string
	}{
		{"builtin view", "view", base + "view"},
		{"system role keeps colon", "system:aggregate-to-view", base + "system:aggregate-to-view"},
		{"slash is escaped", "a/b", base + "a%2Fb"},
		{"percent is escaped", "a%b", base + "a%25b"},
		{"custom dotted", "custom.reader", base + "custom.reader"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clusterRolePath(tc.role); got != tc.want {
				t.Fatalf("clusterRolePath(%q) = %q, want %q", tc.role, got, tc.want)
			}
		})
	}
}

func TestClusterRoleFetchStatusError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		status       int
		wantNil      bool
		wantSentinel bool
		wantSubstr   string
	}{
		{"ok", http.StatusOK, true, false, ""},
		{"unauthorized", http.StatusUnauthorized, false, true, "401 Unauthorized"},
		{"forbidden", http.StatusForbidden, false, true, "403 Forbidden"},
		{"server error", http.StatusInternalServerError, false, false, "fetch status 500"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := clusterRoleFetchStatusError("view", c.status)
			if c.wantNil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if errors.Is(err, ErrClusterAccessDenied) != c.wantSentinel {
				t.Errorf("errors.Is(ErrClusterAccessDenied) = %v, want %v (err=%v)",
					errors.Is(err, ErrClusterAccessDenied), c.wantSentinel, err)
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("error %q missing %q", err.Error(), c.wantSubstr)
			}
			if !strings.Contains(err.Error(), `"view"`) {
				t.Errorf("error %q should name the clusterrole", err.Error())
			}
		})
	}
}

func TestClusterRoleFetchStatusError_Transient(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		status        int
		wantTransient bool
	}{
		{"503 is transient (retried)", http.StatusServiceUnavailable, true},
		{"500 is transient (retried)", http.StatusInternalServerError, true},
		{"429 is transient (retried)", http.StatusTooManyRequests, true},
		{"403 is definitive (not retried)", http.StatusForbidden, false},
		{"401 is definitive (not retried)", http.StatusUnauthorized, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := clusterRoleFetchStatusError("view", c.status)
			if got := isTransientProbeErr(err); got != c.wantTransient {
				t.Fatalf("isTransientProbeErr(status %d) = %v, want %v (err=%v)",
					c.status, got, c.wantTransient, err)
			}
		})
	}
}
