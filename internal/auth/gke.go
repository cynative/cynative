package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"golang.org/x/oauth2"
	container "google.golang.org/api/container/v1"
	"google.golang.org/api/option"
)

const gkeProviderName = "gke"

// GKEAuthArgs holds GKE-specific authentication arguments.
type GKEAuthArgs struct {
	ClusterName string `json:"cluster_name" jsonschema_description:"GKE cluster name. Required for CA certificate resolution."`                   //nolint:lll // struct tags are indivisible
	Location    string `json:"location"     jsonschema_description:"GCP location (e.g. 'us-central1'). Required for CA certificate resolution."`  //nolint:lll // struct tags are indivisible
	Project     string `json:"project"      jsonschema_description:"GCP project ID (e.g. 'my-project'). Required for CA certificate resolution."` //nolint:lll // struct tags are indivisible
}

// gkeGetClusterFunc resolves a GKE cluster's TLS facts (endpoint host + CA).
type gkeGetClusterFunc func(ctx context.Context, ts oauth2.TokenSource, project, location, clusterName string) (clusterTLS, error) //nolint:lll // function-type signature is indivisible

// gkeNewContainerServiceFunc creates a GKE Container API service.
type gkeNewContainerServiceFunc func(ctx context.Context, ts oauth2.TokenSource) (*container.Service, error)

type gkeProvider struct {
	k8sGate[GKEAuthArgs]

	tokenSource         oauth2.TokenSource
	getCluster          gkeGetClusterFunc
	newContainerService gkeNewContainerServiceFunc
	cluster             syncCache[clusterTLS]
}

var (
	_ Provider         = (*gkeProvider)(nil)
	_ ActionAuthorizer = (*gkeProvider)(nil)
	_ CACertProvider   = (*gkeProvider)(nil)
	_ AddrAuthorizer   = (*gkeProvider)(nil)
)

// newGKEProvider constructs a GKE provider backed by the given token source,
// defaulting the GKE-API seams to real implementations. The CA-cert fetch seam
// is a closure over the container-service factory so both remain injectable.
func newGKEProvider(tokenSource oauth2.TokenSource) *gkeProvider {
	p := &gkeProvider{
		tokenSource:         tokenSource,
		newContainerService: defaultGKENewContainerService,
		getCluster:          nil,
	}
	p.getCluster = func(
		ctx context.Context, ts oauth2.TokenSource, project, location, clusterName string,
	) (clusterTLS, error) {
		return defaultGKEGetCluster(ctx, p.newContainerService, ts, project, location, clusterName)
	}
	p.fetchView = p.defaultFetchView // branch-free; body in gke_shell.go.
	p.cacheKey = func(a *GKEAuthArgs) string {
		return a.Project + "/" + a.Location + "/" + a.ClusterName
	}
	p.validate = (*GKEAuthArgs).validate
	p.clusterRole = defaultClusterRole

	return p
}

// tokenWithContext mints a token from ts under the caller's context. oauth2's
// TokenSource.Token takes no context, so a stalled refresh would otherwise be
// uncancellable and could wedge the preflight; the goroutine + select makes the
// wait honor ctx (the abandoned refresh drains into the buffered channel and the
// goroutine exits when it returns). That return is now time-bounded: ADC token
// refreshes are capped (boundedADCContext for token-endpoint creds, the metadata
// client's own timeout in-cluster), so an abandoned goroutine cannot leak
// indefinitely. A tighter ctx cancellation still returns first.
func tokenWithContext(ctx context.Context, ts oauth2.TokenSource) (*oauth2.Token, error) {
	type result struct {
		tok *oauth2.Token
		err error
	}

	ch := make(chan result, 1)
	go func() {
		tok, err := ts.Token()
		ch <- result{tok: tok, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("gke: token refresh cancelled: %w", ctx.Err())
	case r := <-ch:
		return r.tok, r.err
	}
}

func (p *gkeProvider) Name() string {
	return gkeProviderName
}

func (p *gkeProvider) Description() string {
	return "GKE Kubernetes bearer-token auth via GCP Application Default Credentials. " +
		"First resolve the cluster endpoint via the GCP Container API (auth_provider=gcp), then use this provider. " +
		"The CA certificate is auto-resolved from the GKE API; do NOT provide it."
}

// parseGKEArgs unmarshals the gke_auth arguments from the raw JSON.
// Both InjectAuth and CACertData need the same parse, so this avoids duplication.
func parseGKEArgs(rawArgs json.RawMessage) (*GKEAuthArgs, error) {
	return parseAuthArgs[GKEAuthArgs](rawArgs, "gke_auth")
}

// gkeClusterConn assembles the cluster connection for the GKE view fetch. GKE
// authenticates by OAuth bearer token only, so it carries no client cert or
// serverName.
func gkeClusterConn(host, caData string) clusterConn {
	return clusterConn{endpoint: "https://" + host, caData: caData}
}

// validate fails closed unless cluster name, location and project are all set.
// The message matches the action-authorization phrasing so the Tier C k8sGate
// can reuse validate directly.
func (a *GKEAuthArgs) validate() error {
	if a == nil || a.ClusterName == "" || a.Location == "" || a.Project == "" {
		return errors.New("gke_auth.cluster_name, location, and project are required for action authorization")
	}

	return nil
}

// InjectAuth sets the Authorization header using the GCP OAuth2 token.
// The rawArgs parameter is intentionally unused here — GKE auth reuses
// the same Application Default Credentials as the GCP provider. The
// rawArgs only carry CA-related fields consumed by CACertData.
func (p *gkeProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	token, err := p.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to retrieve GCP token for GKE: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	return nil
}

// resolveCluster fetches (and caches) the cluster's endpoint host and CA.
func (p *gkeProvider) resolveCluster(ctx context.Context, args *GKEAuthArgs) (clusterTLS, error) {
	cacheKey := args.Project + "/" + args.Location + "/" + args.ClusterName

	return p.cluster.get(ctx, cacheKey, func(ctx context.Context) (clusterTLS, error) {
		return p.getCluster(ctx, p.tokenSource, args.Project, args.Location, args.ClusterName)
	})
}

// AuthorizeAction enforces the read-only ClusterRole posture for GKE Kubernetes API
// requests via the shared k8sGate. It implements the optional
// auth.ActionAuthorizer interface.
func (p *gkeProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	args, err := parseGKEArgs(rawArgs)
	if err != nil {
		return err
	}

	return p.authorizeAction(ctx, req, args)
}

func (p *gkeProvider) CACertData(ctx context.Context, rawArgs json.RawMessage) (string, error) {
	gkeArgs, err := parseGKEArgs(rawArgs)
	if err != nil {
		return "", err
	}

	if gkeArgs.validate() != nil {
		return "", nil //nolint:nilerr // CACertData tolerates absent/incomplete args; validate() callers get the error.
	}

	ct, err := p.resolveCluster(ctx, gkeArgs)
	if err != nil {
		return "", err
	}

	return ct.caData, nil
}

func (p *gkeProvider) resolveHost(ctx context.Context, args *GKEAuthArgs) (string, error) {
	ct, err := p.resolveCluster(ctx, args)
	if err != nil {
		return "", err
	}

	return ct.host, nil
}

func (p *gkeProvider) AuthorizesHost(ctx context.Context, host string, rawArgs json.RawMessage) (bool, error) {
	return p.authorizesHost(ctx, host, rawArgs, parseGKEArgs, (*GKEAuthArgs).validate, p.resolveHost)
}

// authorizesDialIP reports whether ip may be dialed for this cluster: it denies
// the link-local/loopback/unspecified floor unconditionally, then requires ip to
// equal the cluster's authoritative endpoint IP. GKE's management API returns the
// master endpoint as an IP literal, so there is no DNS step. If ct.host is not an
// IP literal — e.g. the DNS-based control-plane endpoint, which is fronted by a
// shared Google Front End with a public CA and is not safely IP-pinnable — it
// fails closed. Shared by AuthorizesAddr (the main dial path) and the bootstrap
// fetch's dial guard.
func (p *gkeProvider) authorizesDialIP(ctx context.Context, ip netip.Addr, args *GKEAuthArgs) (bool, error) {
	if floorForbidden(ip) {
		return false, nil
	}

	ct, err := p.resolveCluster(ctx, args)
	if err != nil {
		return false, err
	}

	want, err := netip.ParseAddr(ct.host)
	if err != nil {
		return false, fmt.Errorf(
			"gke: endpoint %q is not an IP literal (DNS endpoint is not IP-pinnable): %w", ct.host, err,
		)
	}

	return ip.Unmap() == want.Unmap(), nil
}

// AuthorizesAddr pins the dial to the cluster endpoint's authoritative IP, after
// the unconditional link-local floor in authorizesDialIP.
func (p *gkeProvider) AuthorizesAddr(ctx context.Context, ip netip.Addr, rawArgs json.RawMessage) (bool, error) {
	return p.authorizesAddr(ctx, ip, rawArgs, parseGKEArgs, (*GKEAuthArgs).validate, p.authorizesDialIP)
}

func defaultGKENewContainerService(ctx context.Context, ts oauth2.TokenSource) (*container.Service, error) {
	return container.NewService(ctx, option.WithTokenSource(ts))
}

func defaultGKEGetCluster(
	ctx context.Context,
	newContainerService gkeNewContainerServiceFunc,
	ts oauth2.TokenSource,
	project, location, clusterName string,
) (clusterTLS, error) {
	svc, err := newContainerService(ctx, ts)
	if err != nil {
		return clusterTLS{}, fmt.Errorf("failed to create GKE container service: %w", err)
	}

	name := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, location, clusterName)

	cluster, err := svc.Projects.Locations.Clusters.Get(name).Context(ctx).Do()
	if err != nil {
		return clusterTLS{}, fmt.Errorf("failed to get GKE cluster %q: %w", name, err)
	}

	if cluster.MasterAuth == nil || cluster.MasterAuth.ClusterCaCertificate == "" {
		return clusterTLS{}, fmt.Errorf("GKE cluster %q has no CA certificate data", name)
	}

	if cluster.Endpoint == "" {
		return clusterTLS{}, fmt.Errorf("GKE cluster %q has no endpoint", name)
	}

	return clusterTLS{
		host:   hostFromEndpoint(cluster.Endpoint),
		caData: cluster.MasterAuth.ClusterCaCertificate,
	}, nil
}
