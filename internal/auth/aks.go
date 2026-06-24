package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const aksProviderName = "aks"

// aksAADServerScope is the fixed Microsoft Entra ID audience for AKS API servers.
// All AKS clusters use the same first-party application ID.
const aksAADServerScope = "6dae42f8-4368-4678-94ff-3960e28e3630/.default"

// AKSAuthArgs holds AKS-specific authentication arguments.
type AKSAuthArgs struct {
	ClusterName    string `json:"cluster_name"    jsonschema_description:"AKS cluster name. Required."`                                            //nolint:lll // struct tags are indivisible
	ResourceGroup  string `json:"resource_group"  jsonschema_description:"Azure resource group containing the AKS cluster. Required for CA cert."` //nolint:lll // struct tags are indivisible
	SubscriptionID string `json:"subscription_id" jsonschema_description:"Azure subscription ID. Required for CA cert."`                           //nolint:lll // struct tags are indivisible
}

// aksNewClientFunc creates an ARM ManagedClusters client targeting the resolved
// cloud (sdkCloud pins the ARM endpoint/audience; the zero value defaults to public).
type aksNewClientFunc func(
	subscriptionID string,
	cred azcore.TokenCredential,
	sdkCloud cloud.Configuration,
) (*armcontainerservice.ManagedClustersClient, error)

type aksProvider struct {
	k8sGate[AKSAuthArgs]

	credential azcore.TokenCredential
	newClient  aksNewClientFunc
	sdkCloud   cloud.Configuration // resolved cloud for the ARM ManagedClusters client.
	creds      syncCache[*rest.Config]
	resolver   addrResolver
}

var (
	_ Provider           = (*aksProvider)(nil)
	_ ActionAuthorizer   = (*aksProvider)(nil)
	_ CACertProvider     = (*aksProvider)(nil)
	_ ClientCertProvider = (*aksProvider)(nil)
	_ AddrAuthorizer     = (*aksProvider)(nil)
)

// newAKSProvider constructs an AKS provider backed by the given credential,
// defaulting the ARM-client factory seam to the real implementation.
func newAKSProvider(credential azcore.TokenCredential, sdkCloud cloud.Configuration) *aksProvider {
	p := &aksProvider{
		credential: credential,
		newClient:  defaultAKSNewManagedClustersClient,
		sdkCloud:   sdkCloud,
	}
	p.fetchView = p.defaultFetchView // branch-free; body in aks_shell.go.
	p.cacheKey = func(a *AKSAuthArgs) string {
		return a.SubscriptionID + "/" + a.ResourceGroup + "/" + a.ClusterName
	}
	p.validate = (*AKSAuthArgs).validate
	p.clusterRole = defaultClusterRole
	p.resolver = defaultResolveAddrs

	return p
}

func (p *aksProvider) Name() string {
	return aksProviderName
}

func (p *aksProvider) Description() string {
	return "AKS Kubernetes auth supporting both Entra ID (Azure AD) and Local Accounts (mTLS/Token). " +
		"Requires aks_auth.cluster_name, resource_group, and subscription_id."
}

// parseAKSArgs unmarshals the aks_auth arguments from the raw JSON, returning
// the typed args (nil when the aks_auth key is absent or the input is empty),
// matching the eks/gke nil convention; callers run validate to enforce required
// fields.
func parseAKSArgs(rawArgs json.RawMessage) (*AKSAuthArgs, error) {
	if len(rawArgs) == 0 {
		return nil, nil //nolint:nilnil // empty input means absent args, not an error; matches the eks/gke nil convention.
	}

	return parseAuthArgs[AKSAuthArgs](rawArgs, "aks_auth")
}

// aksClusterTLSMaterial base64-encodes the cluster CA and (for local-account
// mTLS) the client cert+key from the AKS rest.Config. It returns
// (caData, clientCert, clientKey); each is "" when its material is absent, and
// cert and key are encoded only when both are present. Unnamed returns + local
// vars because nonamedreturns is enabled.
func aksClusterTLSMaterial(cfg *rest.Config) (string, string, string) {
	caData := ""
	if len(cfg.CAData) > 0 {
		caData = base64.StdEncoding.EncodeToString(cfg.CAData)
	}

	clientCert, clientKey := "", ""
	if len(cfg.CertData) > 0 && len(cfg.KeyData) > 0 {
		clientCert = base64.StdEncoding.EncodeToString(cfg.CertData)
		clientKey = base64.StdEncoding.EncodeToString(cfg.KeyData)
	}

	return caData, clientCert, clientKey
}

// aksNeedsAADToken reports whether an Entra ID (AAD) bearer must be fetched: only
// when the cluster offers neither a local-account bearer nor a client cert (mTLS).
func aksNeedsAADToken(bearer, clientCert string) bool {
	return bearer == "" && clientCert == ""
}

// aksClusterConn assembles the cluster connection for the AKS view fetch from the
// rest.Config host and the base64 TLS material. The bearer is applied separately
// (bearerInject), after the conditional AAD fetch, so I/O ordering is preserved.
func aksClusterConn(cfgHost, caData, clientCert, clientKey string) clusterConn {
	return clusterConn{
		endpoint:   "https://" + hostFromEndpoint(cfgHost),
		caData:     caData,
		clientCert: clientCert,
		clientKey:  clientKey,
	}
}

// validate fails closed unless cluster name, resource group and subscription
// ID are all set — the exact requirement getClusterConfig enforces. The Tier C
// k8sGate reuses validate as its action-authz guard.
func (a *AKSAuthArgs) validate() error {
	if a == nil || a.ClusterName == "" || a.ResourceGroup == "" || a.SubscriptionID == "" {
		return errors.New("cluster_name, resource_group, and subscription_id are required")
	}

	return nil
}

func (p *aksProvider) getClusterConfig(ctx context.Context, args *AKSAuthArgs) (*rest.Config, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}

	cacheKey := args.SubscriptionID + "/" + args.ResourceGroup + "/" + args.ClusterName

	return p.creds.get(ctx, cacheKey, func(ctx context.Context) (*rest.Config, error) {
		return aksGetClusterConfig(
			ctx, p.newClient, p.credential, p.sdkCloud, args.SubscriptionID, args.ResourceGroup, args.ClusterName,
		)
	})
}

func (p *aksProvider) InjectAuth(req *http.Request, rawArgs json.RawMessage) error {
	aksArgs, err := parseAKSArgs(rawArgs)
	if err != nil {
		return err
	}

	if aksArgs == nil || aksArgs.ClusterName == "" {
		return errors.New("aks_auth.cluster_name is required")
	}

	// If we have full config, attempt local account auth first.
	if aksArgs.ResourceGroup != "" && aksArgs.SubscriptionID != "" {
		cfg, cfgErr := p.getClusterConfig(req.Context(), aksArgs)
		if cfgErr != nil {
			return cfgErr
		}

		// 1. Local Account (Bearer Token)
		if cfg.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
			return nil
		}

		// 2. Local Account (mTLS) - No auth header needed, handled by transport
		if len(cfg.CertData) > 0 && len(cfg.KeyData) > 0 {
			return nil
		}

		// If neither token nor mTLS, fall through to AAD (e.g. if config uses exec plugin).
	}

	// 3. Fallback to Microsoft Entra ID (AAD)
	token, err := p.credential.GetToken(req.Context(), policy.TokenRequestOptions{
		Scopes: []string{aksAADServerScope},
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve Azure token for AKS AAD fallback: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.Token)

	return nil
}

// AuthorizeAction enforces the read-only ClusterRole posture for AKS Kubernetes API
// requests via the shared k8sGate. It implements the optional
// auth.ActionAuthorizer interface.
func (p *aksProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	args, err := parseAKSArgs(rawArgs)
	if err != nil {
		return err
	}

	return p.authorizeAction(ctx, req, args)
}

func (p *aksProvider) CACertData(ctx context.Context, rawArgs json.RawMessage) (string, error) {
	aksArgs, err := parseAKSArgs(rawArgs)
	if err != nil {
		return "", err
	}

	if aksArgs.validate() != nil {
		return "", nil //nolint:nilerr // CACertData tolerates absent/incomplete args; validate() callers get the error.
	}

	cfg, err := p.getClusterConfig(ctx, aksArgs)
	if err != nil {
		return "", err
	}

	if len(cfg.CAData) == 0 {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(cfg.CAData), nil
}

func (p *aksProvider) ClientCertData(ctx context.Context, rawArgs json.RawMessage) (string, string, error) {
	aksArgs, err := parseAKSArgs(rawArgs)
	if err != nil {
		return "", "", err
	}

	if aksArgs.validate() != nil {
		return "", "", nil //nolint:nilerr // ClientCertData tolerates absent/incomplete args; validate() callers get the error.
	}

	cfg, err := p.getClusterConfig(ctx, aksArgs)
	if err != nil {
		return "", "", err
	}

	if len(cfg.CertData) == 0 || len(cfg.KeyData) == 0 {
		return "", "", nil
	}

	return base64.StdEncoding.EncodeToString(cfg.CertData), base64.StdEncoding.EncodeToString(cfg.KeyData), nil
}

func (p *aksProvider) resolveHost(ctx context.Context, args *AKSAuthArgs) (string, error) {
	cfg, err := p.getClusterConfig(ctx, args)
	if err != nil {
		return "", err
	}

	return hostFromEndpoint(cfg.Host), nil
}

func (p *aksProvider) AuthorizesHost(ctx context.Context, host string, rawArgs json.RawMessage) (bool, error) {
	return p.authorizesHost(ctx, host, rawArgs, parseAKSArgs, (*AKSAuthArgs).validate, p.resolveHost)
}

// authorizesDialIP reports whether ip may be dialed for this cluster: it denies
// the link-local/loopback/unspecified floor unconditionally (so a poisoned
// resolution to cloud metadata is rejected even if it lands in the set), then
// pins to the endpoint's resolved addresses. AKS exposes the API server only as
// an FQDN, so it resolves the endpoint host fresh on every call (no cache) and
// fails closed on a resolve error. Shared by AuthorizesAddr (the main dial path)
// and the bootstrap fetch's dial guard. The membership set is built from the same
// resolver the dialer uses, so a rebind to an arbitrary non-floor (public) IP is
// backstopped by the cluster-CA-pinned TLS handshake, not by this set; the set's
// own contribution is the floor plus rejecting a dialed IP that differs from a
// controlled resolution.
func (p *aksProvider) authorizesDialIP(ctx context.Context, ip netip.Addr, args *AKSAuthArgs) (bool, error) {
	if floorForbidden(ip) {
		return false, nil
	}

	cfg, err := p.getClusterConfig(ctx, args)
	if err != nil {
		return false, err
	}

	host := hostFromEndpoint(cfg.Host)

	addrs, err := p.resolver(ctx, host)
	if err != nil {
		return false, fmt.Errorf("aks: resolve endpoint %q: %w", host, err)
	}

	return contains(addrs, ip), nil
}

// AuthorizesAddr pins the dial to the cluster endpoint's exact resolved IP(s),
// after the unconditional link-local floor in authorizesDialIP.
func (p *aksProvider) AuthorizesAddr(ctx context.Context, ip netip.Addr, rawArgs json.RawMessage) (bool, error) {
	return p.authorizesAddr(ctx, ip, rawArgs, parseAKSArgs, (*AKSAuthArgs).validate, p.authorizesDialIP)
}

func defaultAKSNewManagedClustersClient(
	subscriptionID string,
	cred azcore.TokenCredential,
	sdkCloud cloud.Configuration,
) (*armcontainerservice.ManagedClustersClient, error) {
	// Assign unconditionally: a zero cloud.Configuration is safe (the SDK defaults
	// to the public cloud), and a non-empty one pins ARM to the resolved sovereign
	// endpoint so ListClusterUserCredentials targets the right cloud.
	opts := &arm.ClientOptions{} //nolint:exhaustruct // only Cloud set.
	opts.ClientOptions.Cloud = sdkCloud
	return armcontainerservice.NewManagedClustersClient(subscriptionID, cred, opts)
}

// aksGetClusterConfig fetches the user kubeconfig for an AKS cluster via the ARM API
// and parses it into a [*rest.Config].
func aksGetClusterConfig(
	ctx context.Context,
	newClient aksNewClientFunc,
	cred azcore.TokenCredential,
	sdkCloud cloud.Configuration,
	subscriptionID, resourceGroup, clusterName string,
) (*rest.Config, error) {
	client, err := newClient(subscriptionID, cred, sdkCloud)
	if err != nil {
		return nil, fmt.Errorf("failed to create AKS client: %w", err)
	}

	// ListClusterUserCredentials returns the base kubeconfig.
	// For AAD clusters, this contains exec plugin config (which clientcmd handles or we fallback).
	// For local account clusters, this contains embedded mTLS certs or tokens.
	resp, err := client.ListClusterUserCredentials(ctx, resourceGroup, clusterName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list AKS cluster %q user credentials: %w", clusterName, err)
	}

	if len(resp.Kubeconfigs) == 0 || len(resp.Kubeconfigs[0].Value) == 0 {
		return nil, fmt.Errorf("AKS cluster %q returned no kubeconfig credentials", clusterName)
	}

	restCfg, err := clientcmd.RESTConfigFromKubeConfig(resp.Kubeconfigs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AKS kubeconfig for cluster %q: %w", clusterName, err)
	}

	return restCfg, nil
}
