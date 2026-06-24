package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// defaultClusterRole is the built-in read-only ClusterRole used when the operator
// configures none. Provider constructors seed clusterRole with it so a gate is
// never left with an empty (path-breaking) role before the shell applies config.
const defaultClusterRole = "view"

// k8sGate is the generic read-only Kubernetes API authorization path shared by the
// eks/gke/aks/kubernetes providers. It owns the identical validate → resolve →
// classify → authorize sequence and the per-cluster policy cache, while the
// credential and cluster-fact mechanics stay per-provider. The k8s subpackage is
// aliased k8sauthz, so the generic is named k8sGate to avoid confusion.
type k8sGate[A any] struct {
	viewPolicy syncCache[*k8sauthz.ViewPolicy]
	fetchView  func(ctx context.Context, args *A) (*k8sauthz.ViewPolicy, error)
	cacheKey   func(*A) string
	validate   func(*A) error

	// clusterRole is the configured ClusterRole the policy is derived from
	// (default "view"). It is interpolated into the fetch path (via the provider's
	// defaultFetchView) and surfaced in denial messages. Set post-construction by
	// the shell tryRegister* functions.
	clusterRole string
}

// authorizeAction enforces the configured read-only ClusterRole posture for a
// Kubernetes API request: it validates the args, resolves (and caches) the
// cluster's configured ClusterRole policy, classifies the request, and authorizes
// it — failing closed on any resolution error and naming the cluster_role on denial.
func (g *k8sGate[A]) authorizeAction(ctx context.Context, req *http.Request, args *A) error {
	if err := g.validate(args); err != nil {
		return err
	}

	vp, err := g.resolveViewPolicy(ctx, args)
	if err != nil {
		if errors.Is(err, ErrClusterAccessDenied) {
			return err // already a clear, actionable single-line message; do not re-wrap.
		}
		return fmt.Errorf("k8s_hardening: cannot resolve clusterrole %q policy: %w", g.clusterRole, err)
	}

	ri := k8sauthz.Classify(req.Method, req.URL.Path, req.URL.Query())

	if authErr := k8sauthz.Authorize(ri, vp); authErr != nil {
		return fmt.Errorf("cluster_role=%q: %w", g.clusterRole, authErr)
	}

	return nil
}

// resolveViewPolicy fetches (and caches per cluster) the parsed ClusterRole policy.
func (g *k8sGate[A]) resolveViewPolicy(ctx context.Context, args *A) (*k8sauthz.ViewPolicy, error) {
	return g.viewPolicy.get(ctx, g.cacheKey(args), func(ctx context.Context) (*k8sauthz.ViewPolicy, error) {
		return g.fetchView(ctx, args)
	})
}

// authorizesHost is the shared AuthorizesHost body for the managed K8s providers:
// parse the args, validate them, resolve the cluster's endpoint host, and require
// an exact match. The parse/validate/resolveHost seams are passed in (not read
// from gate fields) so providers built via bare struct literals in tests work.
func (g *k8sGate[A]) authorizesHost(
	ctx context.Context,
	host string,
	rawArgs json.RawMessage,
	parse func(json.RawMessage) (*A, error),
	validate func(*A) error,
	resolveHost func(context.Context, *A) (string, error),
) (bool, error) {
	args, err := parse(rawArgs)
	if err != nil {
		return false, err
	}

	if err = validate(args); err != nil {
		return false, err
	}

	h, err := resolveHost(ctx, args)
	if err != nil {
		return false, err
	}

	return host == h, nil
}

// authorizesAddr is the shared AuthorizesAddr body: parse and validate the args,
// then defer to the provider's authorizesDialIP core (which applies the
// link-local floor and the per-provider IP pin).
func (g *k8sGate[A]) authorizesAddr(
	ctx context.Context,
	ip netip.Addr,
	rawArgs json.RawMessage,
	parse func(json.RawMessage) (*A, error),
	validate func(*A) error,
	dial func(context.Context, netip.Addr, *A) (bool, error),
) (bool, error) {
	args, err := parse(rawArgs)
	if err != nil {
		return false, err
	}

	if err = validate(args); err != nil {
		return false, err
	}

	return dial(ctx, ip, args)
}
