package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// kubernetesProviderName is the connector id the model selects via auth_provider.
const kubernetesProviderName = "kubernetes"

// ErrNoCurrentContext marks the ambient "nothing selected" skip: no
// current-context is set. Routed via kubeSkipPolicy to an explicit-gated
// diagnostic (quiet for default discovery, loud when KUBECONFIG was explicitly
// set).
var ErrNoCurrentContext = errors.New(
	"kubernetes: no current-context set",
)

// ErrUnsupportedFeature marks a selected context that uses a kubeconfig feature
// this connector deliberately refuses. Routed via kubeSkipPolicy to an
// explicit-gated diagnostic.
var ErrUnsupportedFeature = errors.New("unsupported kubeconfig feature")

// credMode is the credential mode resolved from a kubeconfig context.
type credMode int

const (
	credBearer credMode = iota // static bearer token (literal or tokenFile).
	credMTLS                   // client certificate + key (mutual TLS).
)

// KubernetesAuthArgs holds generic-Kubernetes auth arguments. It is
// intentionally empty in v1: the connector targets the single configured
// cluster, so the model only needs to select auth_provider:"kubernetes". The
// type is reserved so a future per-call cluster selector is a non-breaking
// addition.
type KubernetesAuthArgs struct{}

// parseKubernetesArgs unmarshals the kubernetes_auth arguments from the raw
// tool JSON, returning nil when the input is empty or the key is absent
// (matching the aks convention) and an error only when the JSON is malformed.
func parseKubernetesArgs(rawArgs json.RawMessage) (*KubernetesAuthArgs, error) {
	if len(rawArgs) == 0 {
		return nil, nil //nolint:nilnil // empty input means absent args, not an error; matches the aks convention.
	}

	return parseAuthArgs[KubernetesAuthArgs](rawArgs, "kubernetes_auth")
}

// rejectUnsafe fails closed when the selected kubeconfig context carries a
// field this connector deliberately refuses to honor: an exec credential
// plugin (arbitrary local code execution — CVE-2022-24817), a legacy
// auth-provider plugin, impersonation (act-as escalation), basic-auth
// username/password (plaintext credentials we will not relay),
// insecure-skip-tls-verify (nullifies the CA trust anchor), a proxy-url (SSRF
// egress redirect), or a non-https / empty-host API server. The connector reads
// only static bearer-token or client-cert credentials; a context needing any
// rejected field is skipped at registration.
func rejectUnsafe(cl *clientcmdapi.Cluster, ai *clientcmdapi.AuthInfo) error {
	if ai.Exec != nil {
		return fmt.Errorf(
			"kubernetes: exec credential plugins are not supported (security): %w", ErrUnsupportedFeature,
		)
	}

	if ai.AuthProvider != nil {
		return fmt.Errorf(
			"kubernetes: auth-provider plugins are not supported (security): %w", ErrUnsupportedFeature,
		)
	}

	if ai.Impersonate != "" || ai.ImpersonateUID != "" ||
		len(ai.ImpersonateGroups) > 0 || len(ai.ImpersonateUserExtra) > 0 {
		return fmt.Errorf("kubernetes: impersonation (act-as) is not supported: %w", ErrUnsupportedFeature)
	}

	if ai.Username != "" || ai.Password != "" {
		return fmt.Errorf("kubernetes: basic-auth username/password is not supported: %w", ErrUnsupportedFeature)
	}

	if cl.InsecureSkipTLSVerify {
		return fmt.Errorf(
			"kubernetes: insecure-skip-tls-verify is not supported (the CA is the trust anchor): %w",
			ErrUnsupportedFeature,
		)
	}

	if cl.ProxyURL != "" {
		return fmt.Errorf("kubernetes: proxy-url is not supported (SSRF risk): %w", ErrUnsupportedFeature)
	}

	u, err := url.Parse(cl.Server)
	if err != nil {
		return fmt.Errorf("kubernetes: parse server URL %q: %w", cl.Server, err)
	}

	if u.Scheme != "https" {
		return fmt.Errorf("kubernetes: server URL must be https, got scheme %q", u.Scheme)
	}

	if u.Hostname() == "" {
		return fmt.Errorf("kubernetes: server URL %q has no host", cl.Server)
	}

	if u.User != nil {
		return fmt.Errorf("kubernetes: server URL %q must not embed credentials", cl.Server)
	}

	return nil
}

// classifyCredential resolves the credential mode from the kubeconfig user.
// Precedence is explicit and fail-safe: a complete client cert AND key (inline
// or file) → mTLS, even if a token is also present (the token is ignored, not
// an error — kubeconfigs carrying both are common); otherwise a token (literal
// or tokenFile) → bearer; otherwise (no usable credential, e.g. a lone cert
// without its key and no token) → error, so the context is skipped.
func classifyCredential(ai *clientcmdapi.AuthInfo) (credMode, error) {
	hasCert := len(ai.ClientCertificateData) > 0 || ai.ClientCertificate != ""
	hasKey := len(ai.ClientKeyData) > 0 || ai.ClientKey != ""
	hasToken := ai.Token != "" || ai.TokenFile != ""

	switch {
	case hasCert && hasKey:
		return credMTLS, nil
	case hasToken:
		return credBearer, nil
	default:
		return credBearer, errors.New("kubernetes: no usable credential (need a bearer token or client cert+key)")
	}
}

// selected holds the raw, safe fields pulled from the chosen kubeconfig
// context. CA / cert / key each appear as either inline bytes OR a file path
// (client-go's *Data field overrides its *path field); resolveSelected reads
// any paths. tokenFile is left as a path and re-read per request.
type selected struct {
	host       string // host of cluster.server (lower-cased, https-validated, port-stripped).
	endpoint   string // full https://host:port of cluster.server (port preserved, for the bootstrap fetch).
	serverName string // cluster.tls-server-name ("" if unset).
	caData     []byte // cluster.certificate-authority-data (inline).
	caFile     string // cluster.certificate-authority (path).
	mode       credMode
	token      string // user.token (literal).
	tokenFile  string // user.tokenFile (path).
	certData   []byte // user.client-certificate-data (inline).
	certFile   string // user.client-certificate (path).
	keyData    []byte // user.client-key-data (inline).
	keyFile    string // user.client-key (path).
}

// selectContext resolves the kubeconfig current-context, failing closed when
// none is set, the named context is absent, or the context references a
// cluster/user that does not exist — so a later nil-map read can never panic.
func selectContext(cfg *clientcmdapi.Config) (*clientcmdapi.Cluster, *clientcmdapi.AuthInfo, error) {
	name := cfg.CurrentContext
	if name == "" {
		return nil, nil, ErrNoCurrentContext
	}

	ctx, ok := cfg.Contexts[name]
	if !ok {
		return nil, nil, fmt.Errorf("kubernetes: context %q not found in kubeconfig", name)
	}

	cl, ok := cfg.Clusters[ctx.Cluster]
	if !ok {
		return nil, nil, fmt.Errorf("kubernetes: cluster %q referenced by context %q not found", ctx.Cluster, name)
	}

	ai, ok := cfg.AuthInfos[ctx.AuthInfo]
	if !ok {
		return nil, nil, fmt.Errorf("kubernetes: user %q referenced by context %q not found", ctx.AuthInfo, name)
	}

	return cl, ai, nil
}

// extractSelected runs the full pure pipeline on an in-memory kubeconfig:
// select the current-context, reject unsafe fields, classify the credential,
// and copy the safe field set. It performs no I/O (paths are copied, not read).
func extractSelected(cfg *clientcmdapi.Config) (selected, error) {
	cl, ai, err := selectContext(cfg)
	if err != nil {
		return selected{}, err
	}

	if err = rejectUnsafe(cl, ai); err != nil {
		return selected{}, err
	}

	mode, err := classifyCredential(ai)
	if err != nil {
		return selected{}, err
	}

	return selected{
		host:       hostFromEndpoint(cl.Server),
		endpoint:   endpointURL(cl.Server),
		serverName: cl.TLSServerName,
		caData:     cl.CertificateAuthorityData,
		caFile:     cl.CertificateAuthority,
		mode:       mode,
		token:      ai.Token,
		tokenFile:  ai.TokenFile,
		certData:   ai.ClientCertificateData,
		certFile:   ai.ClientCertificate,
		keyData:    ai.ClientKeyData,
		keyFile:    ai.ClientKey,
	}, nil
}

// endpointURL normalizes a kubeconfig cluster.server to the https URL used for
// the view-role bootstrap fetch, preserving the host AND port (unlike
// hostFromEndpoint, which is port-stripped for host pinning). rejectUnsafe has
// already validated that server parses as https with a non-empty host.
func endpointURL(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return ""
	}

	return "https://" + u.Host // u.Host preserves host:port.
}

// resolvedCluster is the captured-at-construction view of the target cluster:
// in-memory facts the per-request provider methods read without further I/O.
// caData/clientCert/clientKey are base64-encoded PEM. token is a literal;
// tokenFile is a path re-read per request (so a rotated SA token is picked up).
type resolvedCluster struct {
	host       string
	endpoint   string
	serverName string
	caData     string
	mode       credMode
	token      string
	tokenFile  string
	clientCert string
	clientKey  string
}

// kubernetesClusterConn assembles the cluster connection for the self-managed
// view fetch from the resolvedCluster captured at registration. The endpoint is
// already a full https URL (port preserved).
func kubernetesClusterConn(c resolvedCluster) clusterConn {
	return clusterConn{
		endpoint:   c.endpoint,
		caData:     c.caData,
		clientCert: c.clientCert,
		clientKey:  c.clientKey,
		serverName: c.serverName,
	}
}

// resolveSelected turns a selected (which may reference CA/cert/key files) into
// a resolvedCluster, reading any file paths via readFile and base64-encoding
// the bytes. The bearer tokenFile is NOT read here — it is re-read per request.
func resolveSelected(sel selected, readFile func(string) ([]byte, error)) (resolvedCluster, error) {
	caData, err := materialize(sel.caData, sel.caFile, readFile)
	if err != nil {
		return resolvedCluster{}, fmt.Errorf("kubernetes: read CA: %w", err)
	}

	rc := resolvedCluster{
		host:       sel.host,
		endpoint:   sel.endpoint,
		serverName: sel.serverName,
		caData:     caData,
		mode:       sel.mode,
	}

	if sel.mode == credMTLS {
		cert, certErr := materialize(sel.certData, sel.certFile, readFile)
		if certErr != nil {
			return resolvedCluster{}, fmt.Errorf("kubernetes: read client cert: %w", certErr)
		}

		key, keyErr := materialize(sel.keyData, sel.keyFile, readFile)
		if keyErr != nil {
			return resolvedCluster{}, fmt.Errorf("kubernetes: read client key: %w", keyErr)
		}

		rc.clientCert = cert
		rc.clientKey = key

		return rc, nil
	}

	rc.token = sel.token
	rc.tokenFile = sel.tokenFile

	return rc, nil
}

// materialize returns base64(inline) when inline bytes are present, else reads
// path (when set) and base64-encodes it, else returns "" (no material).
func materialize(inline []byte, path string, readFile func(string) ([]byte, error)) (string, error) {
	if len(inline) > 0 {
		return base64.StdEncoding.EncodeToString(inline), nil
	}

	if path == "" {
		return "", nil
	}

	raw, err := readFile(path)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

// kubernetesProvider is the self-managed Kubernetes connector. It targets the
// single cluster captured from the local kubeconfig at registration and
// enforces the same read-only ClusterRole posture as the cloud K8s connectors via the
// embedded k8sGate.
type kubernetesProvider struct {
	k8sGate[KubernetesAuthArgs]

	cluster  resolvedCluster
	resolver addrResolver
	readFile func(string) ([]byte, error)
}

var (
	_ Provider           = (*kubernetesProvider)(nil)
	_ ActionAuthorizer   = (*kubernetesProvider)(nil)
	_ CACertProvider     = (*kubernetesProvider)(nil)
	_ ClientCertProvider = (*kubernetesProvider)(nil)
	_ ServerNameProvider = (*kubernetesProvider)(nil)
	_ AddrAuthorizer     = (*kubernetesProvider)(nil)
)

// newKubernetesProvider builds a provider over an already-resolved cluster,
// defaulting the address-resolver, file-reader, and view-role fetch seams to
// their real implementations (bodies in kubernetes_shell.go). cacheKey is
// constant and validate is a no-op because v1 targets the single configured
// cluster.
func newKubernetesProvider(cluster resolvedCluster) *kubernetesProvider {
	p := &kubernetesProvider{
		cluster:  cluster,
		resolver: defaultResolveAddrs,
		readFile: defaultReadFile,
	}
	p.fetchView = p.defaultFetchView // branch-free; body in kubernetes_shell.go.
	p.cacheKey = func(*KubernetesAuthArgs) string { return "self" }
	p.validate = func(*KubernetesAuthArgs) error { return nil }
	p.clusterRole = defaultClusterRole

	return p
}

func (p *kubernetesProvider) Name() string {
	return kubernetesProviderName
}

func (p *kubernetesProvider) Description() string {
	return "Self-managed Kubernetes bearer-token or client-certificate auth, sourced from the local kubeconfig " +
		"(KUBECONFIG / ~/.kube/config, current-context). Targets the single configured cluster; pass auth_provider=" +
		"\"kubernetes\". The CA and credentials are resolved from the kubeconfig; do NOT provide them."
}

// bearerToken returns the bearer credential to present: the literal token, or
// the trimmed contents of tokenFile (re-read per call via the injected readFile
// seam, so a rotated ServiceAccount token is picked up). It returns "" for an
// mTLS cluster (no bearer credential).
func (p *kubernetesProvider) bearerToken() (string, error) {
	if p.cluster.mode != credBearer {
		return "", nil
	}

	if p.cluster.tokenFile == "" {
		return p.cluster.token, nil
	}

	raw, err := p.readFile(p.cluster.tokenFile)
	if err != nil {
		return "", fmt.Errorf("kubernetes: read tokenFile %q: %w", p.cluster.tokenFile, err)
	}

	return strings.TrimSpace(string(raw)), nil
}

// InjectAuth attaches the bearer token (re-reading tokenFile per request so a
// rotated SA token is picked up), or no header for mTLS (the transport presents
// the client certificate). rawArgs is unused: v1 targets the single configured
// cluster.
func (p *kubernetesProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	if p.cluster.mode == credMTLS {
		return nil
	}

	token, err := p.bearerToken()
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

// CACertData returns the base64-PEM CA captured from the kubeconfig (empty when
// the cluster uses a publicly-trusted certificate).
func (p *kubernetesProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.cluster.caData, nil
}

// ClientCertData returns the base64-PEM client cert and key for mTLS clusters
// (both empty for bearer-token clusters).
func (p *kubernetesProvider) ClientCertData(_ context.Context, _ json.RawMessage) (string, string, error) {
	return p.cluster.clientCert, p.cluster.clientKey, nil
}

// ServerNameData returns the kubeconfig tls-server-name override (empty when
// unset), used as the TLS verified name for IP endpoints whose CA leaf carries
// only DNS SANs.
func (p *kubernetesProvider) ServerNameData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.cluster.serverName, nil
}

// AuthorizesHost permits only the configured cluster endpoint host.
func (p *kubernetesProvider) AuthorizesHost(_ context.Context, host string, _ json.RawMessage) (bool, error) {
	return host == p.cluster.host, nil
}

// authorizesDialIP enforces the dial-time IP policy: the unconditional
// link-local/loopback/metadata/ULA floor first, then the exact-IP pin. When the
// configured endpoint host is an IP literal it pins to that exact address (no
// DNS); otherwise it re-resolves the FQDN per dial and requires membership in
// the resolved set (the cluster-CA-pinned TLS handshake backstops rebinding).
// Self-managed clusters legitimately use either an IP-literal or a DNS endpoint,
// so unlike the cloud providers (gke pins an IP literal; eks/aks resolve an
// FQDN) this unifies both; the cluster-CA-pinned TLS handshake backstops either
// form. Shared by AuthorizesAddr (the main dial path) and the bootstrap view
// fetch.
func (p *kubernetesProvider) authorizesDialIP(ctx context.Context, ip netip.Addr) (bool, error) {
	if floorForbidden(ip) {
		return false, nil
	}

	if want, err := netip.ParseAddr(p.cluster.host); err == nil {
		return ip.Unmap() == want.Unmap(), nil
	}

	addrs, err := p.resolver(ctx, p.cluster.host)
	if err != nil {
		return false, fmt.Errorf("kubernetes: resolve endpoint %q: %w", p.cluster.host, err)
	}

	return contains(addrs, ip), nil
}

// AuthorizesAddr pins the dial to the configured endpoint after the floor.
// rawArgs is unused: v1 targets the single configured cluster.
func (p *kubernetesProvider) AuthorizesAddr(ctx context.Context, ip netip.Addr, _ json.RawMessage) (bool, error) {
	return p.authorizesDialIP(ctx, ip)
}

// probeAndSeedView validates at registration that the configured ClusterRole is
// fetchable and parseable AND seeds the runtime view-policy cache, so the first
// request skips the redundant fetch through the same lazy path. It resolves
// through resolveViewPolicy (which caches on success) rather than a bare fetch,
// so the eager validation and the cache seed are one call.
func (p *kubernetesProvider) probeAndSeedView(ctx context.Context) error {
	_, err := p.resolveViewPolicy(ctx, nil)

	return err
}

// AuthorizeAction enforces the read-only ClusterRole posture via the shared k8sGate.
func (p *kubernetesProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	args, err := parseKubernetesArgs(rawArgs)
	if err != nil {
		return err
	}

	return p.authorizeAction(ctx, req, args)
}
