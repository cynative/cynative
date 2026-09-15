package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2"

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
		cacheKey:     func(a *gateTestArgs) string { return a.key },
		clusterRole:  "view",
		expectedPort: "443",
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

// TestK8sProviders_expectedPort pins the port every Kubernetes connector binds
// its requests to. The managed three build their bootstrap fetch as
// "https://" + a port-stripped host, so 443 is the port they already validate
// against and the port the gate has to admit; the self-managed connector takes
// whatever the kubeconfig names.
func TestK8sProviders_expectedPort(t *testing.T) {
	t.Parallel()

	t.Run("managed connectors pin the https default", func(t *testing.T) {
		t.Parallel()

		eks := newEKSProvider(aws.Config{})
		gke := newGKEProvider(mockTokenSource(&oauth2.Token{}, nil))
		aks := newAKSProvider(mockCredential(azcore.AccessToken{}, nil), cloud.Configuration{})

		for name, got := range map[string]string{
			"eks": eks.expectedPort, "gke": gke.expectedPort, "aks": aks.expectedPort,
		} {
			if got != "443" {
				t.Errorf("%s expectedPort = %q, want 443", name, got)
			}
		}
	})

	t.Run("self-managed takes the kubeconfig port", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "k3s", authority: "k3s:6443", port: "6443"})
		if p.expectedPort != "6443" {
			t.Errorf("expectedPort = %q, want 6443", p.expectedPort)
		}
	})

	t.Run("a kubeconfig without a port means the https default", func(t *testing.T) {
		t.Parallel()

		p := newKubernetesProvider(resolvedCluster{host: "k8s.example", authority: "k8s.example"})
		if p.expectedPort != "443" {
			t.Errorf("expectedPort = %q, want 443", p.expectedPort)
		}
	})
}

func TestK8sGate_authorizeAction_port(t *testing.T) {
	t.Parallel()

	okArgs := func(t *testing.T) *gateTestArgs {
		t.Helper()

		return &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			return viewPolicyAllowingPods(), nil
		}}
	}

	tests := []struct {
		name, expected, url string
		wantAllowed         bool
	}{
		{"cluster on 6443 accepts its own port", "6443", "https://example:6443/api/v1/pods", true},
		{"cluster on 6443 rejects an omitted port", "6443", "https://example/api/v1/pods", false},
		{"cluster on 6443 rejects the default port", "6443", "https://example:443/api/v1/pods", false},
		{"cluster on 443 accepts an omitted port", "443", "https://example/api/v1/pods", true},
		{"cluster on 443 accepts its own port", "443", "https://example:443/api/v1/pods", true},
		{"cluster on 443 rejects another port", "443", "https://example:8443/api/v1/pods", false},
		{"a leading-zero request port is not the same port", "6443", "https://example:06443/api/v1/pods", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := newGateTest()
			g.expectedPort = tc.expected
			err := g.authorizeAction(context.Background(), actionView(t, http.MethodGet, tc.url), okArgs(t))
			if tc.wantAllowed {
				if err != nil {
					t.Fatalf("authorizeAction(%q) = %v, want allowed", tc.url, err)
				}

				return
			}
			if !errors.Is(err, ErrHostNotAuthorized) {
				t.Fatalf("authorizeAction(%q) = %v, want ErrHostNotAuthorized", tc.url, err)
			}
		})
	}
}

// TestK8sGate_authorizeAction_portOrdering covers where the port check sits: it
// runs before the credentialed ClusterRole fetch, it runs again once that policy
// is cached, and an unconfigured port denies instead of defaulting.
func TestK8sGate_authorizeAction_portOrdering(t *testing.T) {
	t.Parallel()

	t.Run("the port is checked again once the policy is cached", func(t *testing.T) {
		t.Parallel()

		var fetches int

		g := newGateTest()
		g.expectedPort = "6443"
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			fetches++

			return viewPolicyAllowingPods(), nil
		}}

		good := actionView(t, http.MethodGet, "https://example:6443/api/v1/pods")
		if err := g.authorizeAction(context.Background(), good, args); err != nil {
			t.Fatalf("the configured port should be allowed: %v", err)
		}

		bad := actionView(t, http.MethodGet, "https://example/api/v1/pods")
		if err := g.authorizeAction(context.Background(), bad, args); !errors.Is(err, ErrHostNotAuthorized) {
			t.Fatalf("a warm policy cache must not skip the port check, got %v", err)
		}
		if fetches != 1 {
			t.Fatalf("fetches = %d, want the cached policy reused rather than re-fetched", fetches)
		}
	})

	t.Run("an unconfigured port denies rather than defaulting", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		g.expectedPort = ""
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			t.Fatal("fetchView must not run when the port is unconfigured")

			return nil, nil //nolint:nilnil // unreachable after t.Fatal; stub never runs.
		}}
		v := actionView(t, http.MethodGet, "https://example/api/v1/pods")
		if err := g.authorizeAction(context.Background(), v, args); !errors.Is(err, ErrHostNotAuthorized) {
			t.Fatalf("authorizeAction with no configured port = %v, want ErrHostNotAuthorized", err)
		}
	})

	t.Run("a port mismatch is refused before the clusterrole is fetched", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		g.expectedPort = "6443"
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			t.Fatal("fetchView must not run for a request on the wrong port")

			return nil, nil //nolint:nilnil // unreachable after t.Fatal; stub never runs.
		}}
		v := actionView(t, http.MethodGet, "https://example/api/v1/pods")
		if err := g.authorizeAction(context.Background(), v, args); !errors.Is(err, ErrHostNotAuthorized) {
			t.Fatalf("authorizeAction on the wrong port = %v, want ErrHostNotAuthorized", err)
		}
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
		v := actionView(t, http.MethodGet, "https://example/api/v1/pods")
		if err := g.authorizeAction(context.Background(), v, args); err == nil {
			t.Fatal("validate failure must error")
		}
	})

	t.Run("resolve failure is wrapped", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			return nil, errors.New("boom")
		}}
		v := actionView(t, http.MethodGet, "https://example/api/v1/pods")
		err := g.authorizeAction(context.Background(), v, args)
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
		v := actionView(t, http.MethodGet, "https://example/api/v1/pods")
		err := g.authorizeAction(context.Background(), v, args)
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
		v := actionView(t, http.MethodGet, "https://example/api/v1/namespaces/d/pods")
		if err := g.authorizeAction(context.Background(), v, args); err != nil {
			t.Fatalf("list pods should be allowed: %v", err)
		}
	})

	t.Run("authorize deny is forbidden", func(t *testing.T) {
		t.Parallel()

		g := newGateTest()
		args := &gateTestArgs{key: "k", fetch: func() (*k8sauthz.ViewPolicy, error) {
			return viewPolicyAllowingPods(), nil
		}}
		v := actionView(t, http.MethodGet, "https://example/api/v1/namespaces/d/secrets")
		err := g.authorizeAction(context.Background(), v, args)
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
