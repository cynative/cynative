package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// gateTestArgs is a minimal stand-in for the per-provider XAuthArgs types,
// used to exercise k8sGate[A] in isolation from any real cloud provider.
type gateTestArgs struct {
	key   string
	bad   bool
	fetch func() (*k8sauthz.ViewPolicy, error)
}

// newGateTest builds a k8sGate wired to the fields of a single gateTestArgs,
// so each subtest controls validate/fetch/cacheKey behavior independently.
func newGateTest() *k8sGate[gateTestArgs] {
	return &k8sGate[gateTestArgs]{
		fetchView: func(_ context.Context, a *gateTestArgs) (*k8sauthz.ViewPolicy, error) {
			return a.fetch()
		},
		cacheKey:    func(a *gateTestArgs) string { return a.key },
		clusterRole: "view",
		validate: func(a *gateTestArgs) error {
			if a.bad {
				return errors.New("args invalid")
			}

			return nil
		},
	}
}

func viewPolicyAllowingPods() *k8sauthz.ViewPolicy {
	return k8sauthz.BuildViewPolicy([]k8sauthz.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
	})
}

func TestK8sGate_authorizeAction(t *testing.T) {
	t.Parallel()

	t.Run("validate failure is returned before any fetch", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		args := &gateTestArgs{key: "k", bad: true, fetch: func() (*k8sauthz.ViewPolicy, error) {
			t.Fatal("fetchView must not run when validate fails")

			return nil, nil //nolint:nilnil // unreachable after t.Fatal; stub never runs.
		}}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := g.authorizeAction(context.Background(), req, args); err == nil {
			t.Fatal("validate failure must error")
		}
	})

	t.Run("resolve failure is wrapped", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			return nil, errors.New("boom")
		}}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		err := g.authorizeAction(context.Background(), req, args)
		if err == nil || !strings.Contains(err.Error(), `k8s_hardening: cannot resolve clusterrole "view" policy`) {
			t.Fatalf("want wrapped resolve error, got %v", err)
		}
	})

	t.Run("access-denied sentinel surfaces directly", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			return nil, fmt.Errorf(
				"%w: reading clusterrole %q returned k8s API 401 Unauthorized", ErrClusterAccessDenied, "view",
			)
		}}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		err := g.authorizeAction(context.Background(), req, args)
		if !errors.Is(err, ErrClusterAccessDenied) {
			t.Fatalf("want ErrClusterAccessDenied surfaced, got %v", err)
		}
		if strings.Contains(err.Error(), "cannot resolve clusterrole") {
			t.Fatalf("access-denied error must not be re-wrapped, got %v", err)
		}
	})

	t.Run("classify + authorize success", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			return viewPolicyAllowingPods(), nil
		}}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/namespaces/d/pods", nil)
		if err := g.authorizeAction(context.Background(), req, args); err != nil {
			t.Fatalf("list pods should be allowed: %v", err)
		}
	})

	t.Run("authorize deny is forbidden", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			return viewPolicyAllowingPods(), nil
		}}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/namespaces/d/secrets", nil)
		err := g.authorizeAction(context.Background(), req, args)
		if !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("list secrets should be ErrForbidden, got %v", err)
		}
		if !strings.Contains(err.Error(), `cluster_role="view"`) {
			t.Fatalf("deny error should name the cluster_role, got %v", err)
		}
	})
}

func TestK8sGate_resolveViewPolicy_cachesPerKey(t *testing.T) {
	t.Parallel()

	calls := 0
	g := &k8sGate[gateTestArgs]{
		fetchView: func(_ context.Context, _ *gateTestArgs) (*k8sauthz.ViewPolicy, error) {
			calls++

			return viewPolicyAllowingPods(), nil
		},
		cacheKey: func(a *gateTestArgs) string { return a.key },
		validate: func(_ *gateTestArgs) error { return nil },
	}
	args := &gateTestArgs{key: "same"}

	if _, err := g.resolveViewPolicy(context.Background(), args); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if _, err := g.resolveViewPolicy(context.Background(), args); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if calls != 1 {
		t.Fatalf("fetchView called %d times across 2 resolves for the same key, want 1", calls)
	}
}
