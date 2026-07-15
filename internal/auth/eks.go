package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const eksProviderName = "eks"

const eksTokenExpiry = 60 // seconds – must match what EKS's authenticator expects

// EKSAuthArgs holds EKS-specific authentication arguments.
type EKSAuthArgs struct {
	ClusterName string `json:"cluster_name"     jsonschema_description:"AWS EKS cluster name for authentication. Required."`                    //nolint:lll // struct tags are indivisible
	Region      string `json:"region,omitempty" jsonschema_description:"AWS region (e.g. 'us-east-1'). Omit to use the SDK-configured region."` //nolint:lll // struct tags are indivisible
}

// eksPresignFunc presigns an STS GetCallerIdentity request for EKS token generation.
type eksPresignFunc func(ctx context.Context, cfg aws.Config, clusterName string) (string, error)

// eksDescribeClusterFunc resolves an EKS cluster's TLS facts (endpoint host + CA).
type eksDescribeClusterFunc func(ctx context.Context, cfg aws.Config, clusterName string) (clusterTLS, error)

type eksProvider struct {
	k8sGate[EKSAuthArgs]

	cfg             aws.Config
	presign         eksPresignFunc
	describeCluster eksDescribeClusterFunc
	cluster         syncCache[clusterTLS]
	resolver        addrResolver
}

var (
	_ Provider         = (*eksProvider)(nil)
	_ ActionAuthorizer = (*eksProvider)(nil)
	_ CACertProvider   = (*eksProvider)(nil)
	_ AddrAuthorizer   = (*eksProvider)(nil)
)

// newEKSProvider constructs an EKS provider backed by the given config,
// defaulting the STS-presign and DescribeCluster seams to real implementations.
func newEKSProvider(cfg aws.Config) *eksProvider {
	p := &eksProvider{
		cfg:             cfg,
		presign:         defaultEKSPresign,
		describeCluster: defaultEKSDescribeCluster,
	}
	p.fetchView = p.defaultFetchView // branch-free; body in eks_shell.go.
	p.cacheKey = func(a *EKSAuthArgs) string {
		return resolveRegion(a.Region, p.cfg.Region) + "/" + a.ClusterName
	}
	p.validate = (*EKSAuthArgs).validate
	p.clusterRole = defaultClusterRole
	p.resolver = defaultResolveAddrs

	return p
}

func (p *eksProvider) Name() string {
	return eksProviderName
}

func (p *eksProvider) Description() string {
	return "EKS Kubernetes bearer-token auth via STS. Requires eks_auth.cluster_name. " +
		"First resolve the cluster endpoint via the EKS API (auth_provider=aws), then use this provider. " +
		"The CA certificate is auto-resolved from the EKS DescribeCluster API; do NOT provide it."
}

// parseEKSArgs unmarshals the eks_auth arguments from the raw JSON.
// Both InjectAuth and CACertData need the same parse, so this avoids duplication.
func parseEKSArgs(rawArgs json.RawMessage) (*EKSAuthArgs, error) {
	return parseAuthArgs[EKSAuthArgs](rawArgs, "eks_auth")
}

// eksBearerToken assembles the k8s-aws-v1 bearer token from a presigned STS URL.
// Shared by InjectAuth and the bootstrap view fetch (defaultFetchView) so the two
// stay byte-for-byte identical.
func eksBearerToken(presignURL string) string {
	return "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(presignURL))
}

// eksClusterConn assembles the cluster connection for the EKS view fetch. EKS
// authenticates by bearer token only, so it carries no client cert or serverName.
func eksClusterConn(host, caData string) clusterConn {
	return clusterConn{endpoint: "https://" + host, caData: caData}
}

// validate fails closed unless the cluster name is present. The message is the
// action-authorization phrasing because the Tier C k8sGate reuses validate as
// its action-authz guard; the inject/host callers tolerate or wrap as needed.
func (a *EKSAuthArgs) validate() error {
	if a == nil || a.ClusterName == "" {
		return errors.New("eks_auth.cluster_name is required for action authorization")
	}

	return nil
}

func (p *eksProvider) InjectAuth(req *http.Request, rawArgs json.RawMessage) error {
	eksArgs, err := parseEKSArgs(rawArgs)
	if err != nil {
		return err
	}

	if eksArgs == nil || eksArgs.ClusterName == "" {
		return errors.New("eks_auth.cluster_name is required when using the eks auth provider")
	}

	clusterName := eksArgs.ClusterName
	region := eksArgs.Region

	ctx := req.Context()
	cfg := p.cfg
	cfg.Region = resolveRegion(region, cfg.Region)

	if _, err = cfg.Credentials.Retrieve(ctx); err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	presignURL, err := p.presign(ctx, cfg, clusterName)
	if err != nil {
		return fmt.Errorf("failed to presign EKS token request: %w", err)
	}

	token := eksBearerToken(presignURL)
	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

// resolveCluster fetches (and caches) the cluster's endpoint host and CA.
func (p *eksProvider) resolveCluster(ctx context.Context, args *EKSAuthArgs) (clusterTLS, error) {
	cfg := p.cfg
	cfg.Region = resolveRegion(args.Region, cfg.Region)

	cacheKey := cfg.Region + "/" + args.ClusterName

	return p.cluster.get(ctx, cacheKey, func(ctx context.Context) (clusterTLS, error) {
		return p.describeCluster(ctx, cfg, args.ClusterName)
	})
}

// AuthorizeAction enforces the read-only ClusterRole posture for EKS Kubernetes API
// requests via the shared k8sGate. It implements the optional
// auth.ActionAuthorizer interface.
func (p *eksProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	args, err := parseEKSArgs(rawArgs)
	if err != nil {
		return err
	}

	return p.authorizeAction(ctx, req, args)
}

func (p *eksProvider) CACertData(ctx context.Context, rawArgs json.RawMessage) (string, error) {
	eksArgs, err := parseEKSArgs(rawArgs)
	if err != nil {
		return "", err
	}

	if eksArgs.validate() != nil {
		return "", nil //nolint:nilerr // CACertData tolerates absent/incomplete args; validate() callers get the error.
	}

	ct, err := p.resolveCluster(ctx, eksArgs)
	if err != nil {
		return "", err
	}

	return ct.caData, nil
}

func (p *eksProvider) resolveHost(ctx context.Context, args *EKSAuthArgs) (string, error) {
	ct, err := p.resolveCluster(ctx, args)
	if err != nil {
		return "", err
	}

	return ct.host, nil
}

func (p *eksProvider) AuthorizesHost(ctx context.Context, host string, rawArgs json.RawMessage) (bool, error) {
	return p.authorizesHost(ctx, host, rawArgs, parseEKSArgs, (*EKSAuthArgs).validate, p.resolveHost)
}

// authorizesDialIP reports whether ip may be dialed for this cluster: it denies
// the link-local/loopback/unspecified floor unconditionally (so a poisoned
// resolution to cloud metadata is rejected even if it lands in the set), then
// pins to the endpoint's resolved addresses. EKS exposes the API server only as
// an FQDN, so it resolves ct.host fresh on every call (no cache) — the pinned set
// then tracks control-plane ENI rotation — and fails closed on a resolve error.
// Shared by AuthorizesAddr (the main dial path) and the bootstrap fetch's dial
// guard. The membership set is built from the same resolver the dialer uses, so
// a rebind to an arbitrary non-floor (public) IP is backstopped by the
// cluster-CA-pinned TLS handshake, not by this set; the set's own contribution is
// the floor plus rejecting a dialed IP that differs from a controlled resolution.
func (p *eksProvider) authorizesDialIP(ctx context.Context, ip netip.Addr, args *EKSAuthArgs) (bool, error) {
	if floorForbidden(ip) {
		return false, nil
	}

	ct, err := p.resolveCluster(ctx, args)
	if err != nil {
		return false, err
	}

	addrs, err := p.resolver(ctx, ct.host)
	if err != nil {
		return false, fmt.Errorf("eks: resolve endpoint %q: %w", ct.host, err)
	}

	return contains(addrs, ip), nil
}

// AuthorizesAddr pins the dial to the cluster endpoint's exact resolved IP(s),
// after the unconditional link-local floor in authorizesDialIP.
func (p *eksProvider) AuthorizesAddr(ctx context.Context, ip netip.Addr, rawArgs json.RawMessage) (bool, error) {
	return p.authorizesAddr(ctx, ip, rawArgs, parseEKSArgs, (*EKSAuthArgs).validate, p.authorizesDialIP)
}

func defaultEKSDescribeCluster(ctx context.Context, cfg aws.Config, clusterName string) (clusterTLS, error) {
	client := eks.NewFromConfig(cfg)

	out, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return clusterTLS{}, fmt.Errorf("failed to describe EKS cluster %q: %w", clusterName, err)
	}

	if out.Cluster == nil || out.Cluster.CertificateAuthority == nil || out.Cluster.CertificateAuthority.Data == nil {
		return clusterTLS{}, fmt.Errorf("EKS cluster %q has no CA certificate data", clusterName)
	}

	if aws.ToString(out.Cluster.Endpoint) == "" {
		return clusterTLS{}, fmt.Errorf("EKS cluster %q has no endpoint", clusterName)
	}

	return clusterTLS{
		host:   hostFromEndpoint(aws.ToString(out.Cluster.Endpoint)),
		caData: aws.ToString(out.Cluster.CertificateAuthority.Data),
	}, nil
}

// setQueryValue returns a smithy middleware that injects a URL query parameter
// into the outgoing HTTP request. It mirrors [smithyhttp.SetHeaderValue] but for
// query parameters — useful for presigned-URL fields like X-Amz-Expires.
func setQueryValue(key, value string) func(stack *smithymiddleware.Stack) error {
	return func(stack *smithymiddleware.Stack) error {
		return stack.Finalize.Add(
			smithymiddleware.FinalizeMiddlewareFunc(
				"SetQueryValue",
				func(ctx context.Context, in smithymiddleware.FinalizeInput, next smithymiddleware.FinalizeHandler) (
					smithymiddleware.FinalizeOutput, smithymiddleware.Metadata, error,
				) {
					if req, ok := in.Request.(*smithyhttp.Request); ok {
						q := req.URL.Query()
						q.Set(key, value)
						req.URL.RawQuery = q.Encode()
					}

					return next.HandleFinalize(ctx, in)
				},
			),
			smithymiddleware.Before,
		)
	}
}

func defaultEKSPresign(ctx context.Context, cfg aws.Config, clusterName string) (string, error) {
	stsClient := sts.NewFromConfig(cfg)
	presignClient := sts.NewPresignClient(stsClient)

	presignReq, err := presignClient.PresignGetCallerIdentity(
		ctx, &sts.GetCallerIdentityInput{},
		func(po *sts.PresignOptions) {
			po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
				o.APIOptions = append(
					o.APIOptions,
					smithyhttp.SetHeaderValue("x-k8s-aws-id", clusterName),
					setQueryValue("X-Amz-Expires", strconv.Itoa(eksTokenExpiry)),
				)
			})
		},
	)
	if err != nil {
		return "", err
	}

	return presignReq.URL, nil
}
