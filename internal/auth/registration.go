package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2/google"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	awshardening "github.com/cynative/cynative/internal/auth/aws"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
)

// registrationDeps carries every external I/O seam used to register the cloud /
// k8s providers, plus the env/fs seams the explicit-config helpers need. The
// shell (provider_shell.go) builds it with real implementations; tests inject
// fakes. The register* methods are pure routing over these seams and are 100%
// covered.
type registrationDeps struct {
	lookupEnv              func(string) (string, bool)
	fileExists             func(string) bool
	homeDir                string
	awsDefaultProfileCreds bool

	tokenForHost   func(ctx context.Context) (token string, present bool, err error)
	validateGithub func(ctx context.Context, token string) (login string, err error)

	discoverGitLab func(hosts []string) (cred glabCredential, err error)
	buildGitLab    func(cfg GitLabHardeningConfig, host string, cred glabCredential) (*gitlabProvider, error)
	validateGitLab func(ctx context.Context, p *gitlabProvider) (username string, err error)

	loadAWS           func(context.Context) (aws.Config, error)
	retrieveAWS       func(context.Context, aws.Config) error
	validateAWS       func(context.Context, aws.Config) (string, string, string, error) // display, rawARN, account, err.
	resolveScopeAWS   func(ctx context.Context, account, rawARN string, cfg aws.Config) (awshardening.ScopeResult, aws.CredentialsProvider)
	buildAWS          func(aws.Config, aws.CredentialsProvider) (*awsProvider, *eksProvider)
	awsPolicyARN      string
	validateAWSPolicy func(ctx context.Context, cfg aws.Config, policyARN string) error

	findGCP         func(context.Context) (*google.Credentials, error)
	probeGCP        func(context.Context) error
	gcpIdentity     func(context.Context, *google.Credentials) string
	buildGCP        func(*google.Credentials) (*gcpProvider, *gkeProvider)
	gcpRole         string
	validateGCPRole func(ctx context.Context, creds *google.Credentials, role string) error

	newAzure            func() (azcore.TokenCredential, error)
	probeAzure          func(context.Context, azcore.TokenCredential) error
	azureIdentity       func(context.Context, azcore.TokenCredential) string
	buildAzure          func(azcore.TokenCredential) (*azureProvider, *aksProvider)
	azureRoleDefinition string
	validateAzureRole   func(ctx context.Context, cred azcore.TokenCredential, roleDef string) (string, error)

	loadKube       func() (resolvedCluster, error, error)
	buildKube      func(resolvedCluster) *kubernetesProvider
	probeKube      func(ctx context.Context, p *kubernetesProvider) error
	k8sClusterRole string
}

// identityProbeTimeout bounds each connector's display-only identity capture so a
// slow tokeninfo/token-acquire cannot stall startup past the liveness budget.
const identityProbeTimeout = credentialProbeTimeout

// skipOutcome builds a single-status outcome for a skipped connector, computing
// visibility from the (already-escalated) policy via the same shouldEmit primitive
// the prior emit path used — preserving ambient-quiet.
func skipOutcome(name string, explicit, verbose bool, policy emitPolicy, reason string) connectorOutcome {
	return connectorOutcome{
		providers: nil,
		statuses:  []ConnectorStatus{{Name: name, Reason: reason}}, //nolint:exhaustruct // skip: Available=false.
		visible:   []bool{shouldEmit(policy, explicit, verbose)},
	}
}

// availStatus builds an available, always-visible ConnectorStatus.
func availStatus(name, posture, identity string, warn bool) ConnectorStatus {
	return ConnectorStatus{Name: name, Available: true, Warn: warn, Posture: posture, Identity: identity, Reason: ""}
}

// boundedIdentity runs a display-only identity capture under a HARD wall-clock
// bound: fn runs in a goroutine and, if it does not return within timeout,
// boundedIdentity returns "" immediately (the goroutine is abandoned and its
// result discarded — acceptable for a best-effort display probe). This does not
// rely on fn honoring ctx, so a token-source acquisition without a context
// parameter cannot stall startup. The timeout is a parameter so tests
// can use a tiny one; production callers pass identityProbeTimeout.
func boundedIdentity(ctx context.Context, timeout time.Duration, fn func(context.Context) string) string {
	ictx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan string, 1) // buffered so the abandoned goroutine never blocks.
	go func() { done <- fn(ictx) }()

	select {
	case id := <-done:
		return id
	case <-ictx.Done():
		return ""
	}
}

// registerAWS loads config, then validates the credential against AWS: Retrieve
// resolves it (which does NOT contact AWS for static env/file keys) and STS
// GetCallerIdentity is the live liveness check that also yields the display
// identity. On a successful probe the eager scope resolution runs fail-soft to
// determine the sts= label and build the pre-scoped credential chain. The probe
// is ctx-bounded and retried once on a transient error. A load failure is always
// loud; a credential failure is explicit-gated, escalated to loud when transient.
func (d *registrationDeps) registerAWS(ctx context.Context, verbose bool) connectorOutcome {
	cfg, loadErr := d.loadAWS(ctx)

	var (
		credErr     error
		identity    string
		scopeResult awshardening.ScopeResult
		scoped      aws.CredentialsProvider
	)
	if loadErr == nil {
		pctx, cancel := context.WithTimeout(ctx, credentialProbeTimeout)
		defer cancel()

		credErr = retryProbe(func() error {
			if err := d.retrieveAWS(pctx, cfg); err != nil {
				return err
			}
			display, rawARN, account, err := d.validateAWS(pctx, cfg) // GCI: liveness + identity, bounded by pctx.
			if err != nil {
				return err
			}
			identity = display
			// Eager scope is fail-soft (never returns an error), so it does not
			// trigger a retry and runs exactly once on the successful probe.
			scopeResult, scoped = d.resolveScopeAWS(pctx, account, rawARN, cfg)

			return nil
		})
	}

	if skipped, policy, msg := awsSkipResult(loadErr, credErr); skipped {
		explicit := awsExplicitlyConfigured(d.lookupEnv, d.fileExists, d.homeDir, d.awsDefaultProfileCreds)

		return skipOutcome(awsProviderName, explicit, verbose,
			escalateForTransient(policy, cmpErr(loadErr, credErr)), msg)
	}

	vctx, vcancel := context.WithTimeout(ctx, ceilingValidationTimeout)
	defer vcancel()
	if verr := retryProbe(func() error { return d.validateAWSPolicy(vctx, cfg, d.awsPolicyARN) }); verr != nil {
		explicit := awsExplicitlyConfigured(d.lookupEnv, d.fileExists, d.homeDir, d.awsDefaultProfileCreds)

		return skipOutcome(awsProviderName, explicit, verbose,
			escalateForTransient(emitWhenExplicitOrVerbose, verr),
			fmt.Sprintf("aws_hardening: skipped (policy validation failed): %v", verr))
	}

	awsProv, eks := d.buildAWS(cfg, scoped)
	posture := buildPosture(awsAccess(d.awsPolicyARN), awsEnforced(scopeResult), awsPostureLabel(d.awsPolicyARN))
	status := availStatus(awsProviderName, posture, identity, false)
	status.Managed = eksProviderName

	return connectorOutcome{
		providers: []Provider{awsProv, eks},
		statuses:  []ConnectorStatus{status},
		visible:   []bool{true},
	}
}

// registerGCP discovers ADC and validates it by minting a token (the live check)
// regardless of explicit config, so a host whose ADC/metadata source cannot
// actually mint a token is not registered. The probe is ctx-bounded and retried
// once on a transient error. Any skip is explicit-gated, escalated to loud when
// transient. On success it captures a bounded, display-only identity.
func (d *registrationDeps) registerGCP(ctx context.Context, verbose bool) connectorOutcome {
	// findGCP MUST use the unbounded ctx: google.FindDefaultCredentials' returned
	// TokenSource retains the supplied context, and the registered provider mints
	// tokens from it for the whole session. Only the probe is bounded — and it
	// builds a SEPARATE source (probeGCPToken), so cancelling pctx never poisons
	// the registered source.
	creds, findErr := d.findGCP(ctx)

	var probeErr error
	if findErr == nil {
		pctx, cancel := context.WithTimeout(ctx, credentialProbeTimeout)
		defer cancel()

		probeErr = retryProbe(func() error { return d.probeGCP(pctx) })
	}

	if skipped, msg := gcpSkipResult(findErr, probeErr); skipped {
		explicit := gcpExplicitlyConfigured(d.lookupEnv, d.fileExists, d.homeDir)

		return skipOutcome(gcpProviderName, explicit, verbose,
			escalateForTransient(emitWhenExplicitOrVerbose, cmpErr(findErr, probeErr)), msg)
	}

	vctx, vcancel := context.WithTimeout(ctx, ceilingValidationTimeout)
	defer vcancel()
	if verr := retryProbe(func() error { return d.validateGCPRole(vctx, creds, d.gcpRole) }); verr != nil {
		explicit := gcpExplicitlyConfigured(d.lookupEnv, d.fileExists, d.homeDir)

		return skipOutcome(gcpProviderName, explicit, verbose,
			escalateForTransient(emitWhenExplicitOrVerbose, verr),
			fmt.Sprintf("gcp_hardening: skipped (role validation failed): %v", verr))
	}

	identity := boundedIdentity(ctx, identityProbeTimeout, func(ictx context.Context) string {
		return d.gcpIdentity(ictx, creds)
	})
	gcpProv, gke := d.buildGCP(creds)

	posture := buildPosture(gcpAccess(d.gcpRole), enforcedClient, gcpPostureLabel(d.gcpRole))
	status := availStatus(gcpProviderName, posture, identity, false)
	status.Managed = gkeProviderName

	return connectorOutcome{
		providers: []Provider{gcpProv, gke},
		statuses:  []ConnectorStatus{status},
		visible:   []bool{true},
	}
}

// registerAzure builds the credential chain and validates it by minting an ARM
// token (the live check) regardless of explicit config — removing the prior
// optimistic registration, so a host with no usable Azure credential is not
// registered. The probe is ctx-bounded and retried once on a transient error.
// Any skip is explicit-gated, escalated to loud when transient. On success it
// captures a bounded, display-only identity. The credential chain is unchanged
// (its own subprocess auth — az/azd/pwsh — is acceptable).
func (d *registrationDeps) registerAzure(ctx context.Context, verbose bool) connectorOutcome {
	cred, chainErr := d.newAzure()

	var probeErr error
	if chainErr == nil {
		pctx, cancel := context.WithTimeout(ctx, credentialProbeTimeout)
		defer cancel()

		probeErr = retryProbe(func() error { return d.probeAzure(pctx, cred) })
	}

	if skipped, msg := azureSkipResult(chainErr, probeErr); skipped {
		explicit := azureExplicitlyConfigured(d.lookupEnv)

		return skipOutcome(azureProviderName, explicit, verbose,
			escalateForTransient(emitWhenExplicitOrVerbose, cmpErr(chainErr, probeErr)), msg)
	}

	vctx, vcancel := context.WithTimeout(ctx, ceilingValidationTimeout)
	defer vcancel()
	var guid string
	if verr := retryProbe(func() error {
		g, e := d.validateAzureRole(vctx, cred, d.azureRoleDefinition)
		guid = g
		return e
	}); verr != nil {
		explicit := azureExplicitlyConfigured(d.lookupEnv)

		return skipOutcome(azureProviderName, explicit, verbose,
			escalateForTransient(emitWhenExplicitOrVerbose, verr),
			fmt.Sprintf("azure_hardening: skipped (role definition validation failed): %v", verr))
	}

	identity := boundedIdentity(ctx, identityProbeTimeout, func(ictx context.Context) string {
		return d.azureIdentity(ictx, cred)
	})
	azureProv, aks := d.buildAzure(cred)

	posture := buildPosture(
		azureAccess(d.azureRoleDefinition),
		enforcedClient,
		azurePostureLabel(d.azureRoleDefinition, guid),
	)
	status := availStatus(azureProviderName, posture, identity, false)
	status.Managed = aksProviderName

	return connectorOutcome{
		providers: []Provider{azureProv, aks},
		statuses:  []ConnectorStatus{status},
		visible:   []bool{true},
	}
}

// registerKube loads the selected cluster, routing any skip by failure type: a
// load failure or structural error is always loud; no-current-context and
// unsupported-feature are loud only when the kubeconfig was explicitly selected.
// After a successful load it eagerly validates the cluster via a dial-guarded
// ClusterRole fetch (probeKube): a probe failure is explicit-gated, escalated to
// loud when transient. The display identity is the resolved API-server host.
func (d *registrationDeps) registerKube(verbose bool) connectorOutcome {
	rc, loadErr, postErr := d.loadKube()

	if skipped, policy, msg := kubeSkipResult(loadErr, postErr); skipped {
		explicit := kubeExplicitlyConfigured(d.lookupEnv)

		return skipOutcome(kubernetesProviderName, explicit, verbose, policy, msg)
	}

	p := d.buildKube(rc)

	pctx, cancel := context.WithTimeout(context.Background(), credentialProbeTimeout)
	defer cancel()

	if err := retryProbe(func() error { return d.probeKube(pctx, p) }); err != nil {
		explicit := kubeExplicitlyConfigured(d.lookupEnv)
		policy := escalateForTransient(emitWhenExplicitOrVerbose, err)

		return skipOutcome(kubernetesProviderName, explicit, verbose, policy,
			fmt.Sprintf("kubernetes_hardening: skipped (cluster validation failed): %v", err))
	}

	posture := buildPosture(k8sAccess(d.k8sClusterRole), enforcedClient, k8sPostureLabel(d.k8sClusterRole))

	return connectorOutcome{
		providers: []Provider{p},
		statuses:  []ConnectorStatus{availStatus(kubernetesProviderName, posture, rc.host, false)},
		visible:   []bool{true},
	}
}

// githubOutcome resolves the gh token and, when present, eagerly validates it with
// a hardened /user→/rate_limit probe before registering. A resolution error is a
// LOUD operational skip; a genuinely absent token is a quiet ambient skip; a
// present-but-invalid token is a LOUD skip; a transient probe error is retried then
// LOUD. Success registers with the @login identity (empty when validated via the
// /rate_limit fallback).
func (d *registrationDeps) githubOutcome(
	ctx context.Context, ghCfg GithubHardeningConfig, verbose bool,
) connectorOutcome {
	pctx, cancel := context.WithTimeout(ctx, credentialProbeTimeout)
	defer cancel()

	token, present, err := d.tokenForHost(pctx)
	if err != nil {
		policy := escalateForTransient(emitWhenExplicitOrVerbose, err)

		return skipOutcome(githubProviderName, true, verbose, policy,
			fmt.Sprintf("github_hardening: skipped (token resolution failed): %v", err))
	}

	if !present {
		return connectorOutcome{} //nolint:exhaustruct // nothing registered, nothing visible.
	}

	var login string

	if perr := retryProbe(func() error {
		l, e := d.validateGithub(pctx, token)
		login = l

		return e
	}); perr != nil {
		policy := escalateForTransient(emitWhenExplicitOrVerbose, perr)

		return skipOutcome(githubProviderName, true, verbose, policy,
			fmt.Sprintf("github_hardening: skipped (token validation failed): %v", perr))
	}

	exposure := githubhardening.BuildExposure(ghCfg.Permissions)
	posture, warn := githubPosture(exposure, ghCfg.Permissions)
	gh := newGithubProvider(token, exposure, githubhardening.NewTableSource(ghCfg.Config, newGithubOpenAPIFetcher()))
	gh.errOut = os.Stderr

	return connectorOutcome{
		providers: []Provider{gh},
		statuses:  []ConnectorStatus{availStatus(githubProviderName, posture, login, warn)},
		visible:   []bool{true},
	}
}

// gitlabOutcome discovers the gitlab token (env or glab config) and, when present,
// builds the provider and eagerly validates the token with a dial-guarded GET
// /api/v4/user before registering — so Available means validated-live this startup
// and the identity is the @username. A genuinely absent token is a quiet ambient
// skip; an unreadable ca_cert is a LOUD config skip; a present-but-invalid token is
// a LOUD skip (a transient probe error is retried, then escalated loud).
func (d *registrationDeps) gitlabOutcome(
	ctx context.Context, glCfg GitLabHardeningConfig, verbose bool,
) connectorOutcome {
	host := resolveGitLabHost(glCfg.Host)
	served := servedHostOf(host, glCfg.APIHost)

	cred, err := d.discoverGitLab(gitlabTokenHosts(glCfg.Host, glCfg.APIHost, served))
	if err != nil {
		return skipOutcome(gitlabProviderName, true, verbose, emitAlways,
			fmt.Sprintf("gitlab_hardening: skipped (token resolution failed): %v", err))
	}
	if cred.AccessToken == "" {
		return connectorOutcome{} //nolint:exhaustruct // no token: quiet ambient skip.
	}

	gl, err := d.buildGitLab(glCfg, host, cred)
	if err != nil {
		return skipOutcome(gitlabProviderName, true, verbose, emitAlways,
			fmt.Sprintf("gitlab_hardening: skipped (provider build failed): %v", err))
	}

	pctx, cancel := context.WithTimeout(ctx, credentialProbeTimeout)
	defer cancel()

	var username string

	if perr := retryProbe(func() error {
		u, e := d.validateGitLab(pctx, gl)
		username = u

		return e
	}); perr != nil {
		policy := escalateForTransient(emitWhenExplicitOrVerbose, perr)

		return skipOutcome(gitlabProviderName, true, verbose, policy,
			fmt.Sprintf("gitlab_hardening: skipped (token validation failed): %v", perr))
	}

	exposure := gitlabclass.BuildExposure(glCfg.Permissions)
	posture, warn := gitlabPosture(exposure, glCfg.Permissions)

	return connectorOutcome{
		providers: []Provider{gl},
		statuses:  []ConnectorStatus{availStatus(gitlabProviderName, posture, gitlabIdentity(username, served), warn)},
		visible:   []bool{true},
	}
}
