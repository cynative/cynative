package auth

import (
	"context"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
	"golang.org/x/oauth2/google"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	awshardening "github.com/cynative/cynative/internal/auth/aws"
	azurehardening "github.com/cynative/cynative/internal/auth/azure"
	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
	"github.com/cynative/cynative/internal/cache"
)

// GithubHardeningConfig configures the GitHub connector: the resolved exposure
// permissions and the shared cache config for the category table. Defined here
// to keep internal/auth free of internal/config import cycles. The CLI
// composition root builds this from internal/config.Config.Connectors.Github.
type GithubHardeningConfig struct {
	cache.Config

	Permissions map[string]string
}

// GitLabHardeningConfig is the cfg.Connectors.GitLab subset relevant to provider
// construction. Defined here to keep internal/auth free of internal/config import
// cycles. The CLI composition root builds this from
// internal/config.Config.Connectors.GitLab.
type GitLabHardeningConfig struct {
	cache.Config

	Host                string
	APIHost             string
	AllowPrivateNetwork bool
	CACertPath          string
	Permissions         map[string]string
}

// AWSHardeningConfig is the cfg.Connectors.AWS subset relevant to provider
// construction. Defined here to keep internal/auth free of internal/config
// import cycles. The CLI composition root builds this from
// internal/config.Config.Connectors.AWS.
type AWSHardeningConfig struct {
	cache.Config

	PolicyARN string
}

// GCPHardeningConfig is the cfg.Connectors.GCP subset relevant to provider
// construction. Defined here to keep internal/auth free of internal/config
// import cycles. The CLI composition root builds this from
// internal/config.Config.Connectors.GCP.
type GCPHardeningConfig struct {
	cache.Config

	Role string
}

// AzureHardeningConfig is the cfg.Connectors.Azure subset relevant to provider
// construction. Defined here to keep internal/auth free of internal/config
// import cycles. The CLI composition root builds this from
// internal/config.Config.Connectors.Azure.
type AzureHardeningConfig struct {
	cache.Config

	RoleDefinition string
	// Cloud selects the Azure cloud (config override; "auto"/"" = auto-detect via
	// AZURE_AUTHORITY_HOST then the Azure CLI config, else public). Governs both the
	// azure and aks connectors, which share the resolved cloud + credential chain.
	Cloud string
}

// EKSHardeningConfig is the cfg.Connectors.EKS subset relevant to EKS provider
// construction. ClusterRole selects the read-only ClusterRole the Kubernetes
// authorization gate derives its allow-policy from (default "view"). Defined here
// to keep internal/auth free of internal/config import cycles.
type EKSHardeningConfig struct {
	ClusterRole string
}

// GKEHardeningConfig is the cfg.Connectors.GKE subset; see EKSHardeningConfig.
type GKEHardeningConfig struct {
	ClusterRole string
}

// AKSHardeningConfig is the cfg.Connectors.AKS subset; see EKSHardeningConfig.
type AKSHardeningConfig struct {
	ClusterRole string
}

// KubernetesHardeningConfig is the cfg.Connectors.Kubernetes subset relevant to
// provider construction. Defined here to keep internal/auth free of
// internal/config import cycles. The CLI composition root builds this from
// internal/config.Config.Connectors.Kubernetes. It mirrors the sibling K8s
// hardening configs (EKS/GKE/AKS): the connector discovers its cluster purely
// from the local kubeconfig (kubectl-default), so the only knob is the
// read-only ClusterRole. Unlike the cloud connectors it has no cache.Config and
// does not use the shared cache: there is no remote permission catalog to cache
// (only the in-memory-cached ClusterRole policy).
type KubernetesHardeningConfig struct {
	ClusterRole string // read-only ClusterRole policy source (default "view").
}

const (
	smithyHTTPTimeout = 30 * time.Second
	policyCacheSize   = 2048
)

// GetProviders discovers available auth providers by fanning out the five
// registrars concurrently. Each registrar's visible ConnectorStatus is emitted
// to onStatus (nil-safe) inline as it completes — so fast connectors stream
// their status before slow ones finish. onStatus is never called concurrently:
// a single consumer goroutine drains the outcomes channel.
//
// It lives in the imperative shell (_shell.go) because it probes the real
// environment and calls the real cloud-SDK entry points. It is integration-
// tested and excluded from the unit-coverage gate.
func GetProviders(cfg HardeningConfig, verbose bool, onStatus func(ConnectorStatus)) []Provider {
	deps := buildRegistrationDeps(cfg)
	ctx := context.Background()

	return driveConcurrent([]func() connectorOutcome{
		func() connectorOutcome { return deps.githubOutcome(ctx, cfg.Github, verbose) },
		func() connectorOutcome { return deps.gitlabOutcome(ctx, cfg.GitLab, verbose) },
		func() connectorOutcome { return deps.registerAWS(ctx, verbose) },
		func() connectorOutcome { return deps.registerGCP(ctx, verbose) },
		func() connectorOutcome { return deps.registerAzure(ctx, verbose) },
		func() connectorOutcome { return deps.registerKube(verbose) },
	}, onStatus)
}

// buildRegistrationDeps wires the real I/O seams for the registration router and
// sets the inventory posture labels + display-only identity seams. The provider
// builders set the per-provider clusterRole fields the registration router does
// not touch. Shell only.
func buildRegistrationDeps(cfg HardeningConfig) *registrationDeps {
	// Resolve the Azure target cloud once (config override → AZURE_AUTHORITY_HOST →
	// az CLI config → public) and thread it to the credential chain, the probe
	// scope, and both the azure/aks providers — matching tryRegisterAzure.
	azureCloud := azurehardening.ResolveCloudFromEnv(cfg.Azure.Cloud, os.LookupEnv)

	return &registrationDeps{ //nolint:exhaustruct // identity seams set inline below.
		lookupEnv:              os.LookupEnv,
		fileExists:             fileExists,
		homeDir:                homeDirOrEmpty(),
		awsDefaultProfileCreds: awsDefaultProfileFileHasCreds(),
		scopeNotifyOut:         os.Stderr,

		tokenForHost:   resolveGithubToken,
		validateGithub: validateGithubToken,

		discoverGitLab: discoverGitLabCred,
		buildGitLab:    buildGitLabProvider,
		validateGitLab: validateGitLabToken,

		loadAWS: func(ctx context.Context) (aws.Config, error) {
			return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithLogger(logging.Nop{}))
		},
		retrieveAWS: func(ctx context.Context, c aws.Config) error {
			_, err := c.Credentials.Retrieve(ctx)

			return err
		},
		validateAWS: validateAWSIdentity,
		resolveScopeAWS: func(ctx context.Context, account, rawARN string, c aws.Config) (awshardening.ScopeResult, aws.CredentialsProvider) {
			return resolveScopeAWS(ctx, account, rawARN, cfg.AWS.PolicyARN, c)
		},
		buildAWS: func(c aws.Config, scoped aws.CredentialsProvider) (*awsProvider, *eksProvider) {
			hardened := buildHardenedAWSProvider(c, cfg.AWS, scoped)
			eks := newEKSProvider(c)
			eks.clusterRole = cfg.EKS.ClusterRole

			return hardened, eks
		},
		awsPolicyARN:      cfg.AWS.PolicyARN,
		validateAWSPolicy: validateAWSPolicy,

		// withBoundedTokenRefresh gives the retained session token source a
		// client-side HTTP timeout, so every refresh is bounded even though ctx is
		// (deliberately) deadline-free and oauth2.TokenSource.Token takes no context.
		findGCP: func(ctx context.Context) (*google.Credentials, error) {
			return google.FindDefaultCredentials(withBoundedTokenRefresh(ctx), gcpScope)
		},
		probeGCP:    probeGCPToken,
		gcpIdentity: gcpRegistrationIdentity,
		buildGCP: func(creds *google.Credentials) (*gcpProvider, *gkeProvider) {
			gke := newGKEProvider(creds.TokenSource)
			gke.clusterRole = cfg.GKE.ClusterRole

			return buildHardenedGCPProvider(creds.TokenSource, cfg.GCP), gke
		},
		gcpRole:         cfg.GCP.Role,
		validateGCPRole: validateGCPRole,

		newAzure: func() (azcore.TokenCredential, error) { return azurehardening.NewCredentialChain(azureCloud) },
		probeAzure: func(ctx context.Context, cred azcore.TokenCredential) error {
			return probeAzureToken(ctx, cred, azureCloud.Scope)
		},
		azureIdentity: func(ctx context.Context, cred azcore.TokenCredential) string {
			return azureRegistrationIdentity(ctx, cred, azureCloud.Scope)
		},
		buildAzure: func(cred azcore.TokenCredential) (*azureProvider, *aksProvider) {
			aks := newAKSProvider(cred, azurehardening.ToSDKCloud(azureCloud))
			aks.clusterRole = cfg.AKS.ClusterRole

			return buildHardenedAzureProvider(cred, cfg.Azure, azureCloud), aks
		},
		azureRoleDefinition: cfg.Azure.RoleDefinition,
		validateAzureRole: func(ctx context.Context, cred azcore.TokenCredential, roleDef string) (string, error) {
			return validateAzureRole(ctx, cred, azureCloud, roleDef)
		},

		loadKube: loadSelectedCluster,
		buildKube: func(rc resolvedCluster) *kubernetesProvider {
			p := newKubernetesProvider(rc)
			p.clusterRole = cfg.Kubernetes.ClusterRole

			return p
		},
		probeKube: func(ctx context.Context, p *kubernetesProvider) error {
			return p.probeAndSeedView(ctx)
		},
		k8sClusterRole: cfg.Kubernetes.ClusterRole,
	}
}

// validateAWSIdentity is the AWS registration liveness check that also returns a
// display identity, raw ARN, and account ID: it calls sts:GetCallerIdentity (the
// live check) and formats "<account> · <arn>" as the display string. The raw ARN
// and account are threaded to the eager scope resolution (resolveScopeAWS).
func validateAWSIdentity(ctx context.Context, c aws.Config) (string, string, string, error) {
	c.Region = resolveRegion(c.Region)
	out, err := sts.NewFromConfig(c).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", "", err
	}
	rawARN := aws.ToString(out.Arn)
	account := aws.ToString(out.Account)
	display := account + " · " + rawARN

	return display, rawARN, account, nil
}

// resolveScopeAWS performs the eager STS credential-scope resolution at
// registration time. It classifies the caller ARN, builds a ScopedProvider via
// ResolveScope, and returns the structured ScopeResult plus the pre-built scoped
// chain. It is fail-soft: a transient error returns the decided-mode result so AWS
// stays available; only a definitive degrade renders Mode=CredScopeDisabled.
// The chain is always valid (wraps a ScopedProvider that resolves the true scope at
// request time).
func resolveScopeAWS(
	ctx context.Context, account, rawARN, policyARN string, cfg aws.Config,
) (awshardening.ScopeResult, aws.CredentialsProvider) {
	_ = account // available for future use (e.g. partition-aware policy selection).
	cfg.Region = resolveRegion(cfg.Region)
	decision := awshardening.DetectCredScope(rawARN)
	result := awshardening.ResolveScope(ctx, decision, sts.NewFromConfig(cfg), policyARN, cfg.Credentials, os.Stderr)

	return result, result.Credentials
}

// gcpRegistrationIdentity resolves a best-effort display identity: project from
// the project joined with the principal from the tokeninfo prober. The project is
// creds.ProjectID, falling back to the prober's resolved project (quota_project_id,
// e.g. for gcloud authorized-user ADC where creds.ProjectID is empty). Probe
// failure degrades to project-only (or ""). Display-only; never fails
// registration. The caller bounds ctx (identityProbeTimeout).
func gcpRegistrationIdentity(ctx context.Context, creds *google.Credentials) string {
	project := ""
	if creds != nil {
		project = creds.ProjectID
	}
	prober := gcphardening.NewIdentityProber(gcphardening.IdentityConfig{}) //nolint:exhaustruct // defaults.
	principal, probeProject, _ := prober.Probe(ctx)
	if project == "" {
		// gcloud authorized-user ADC leaves creds.ProjectID empty; the prober
		// resolves the active project (quota_project_id), so fall back to it.
		project = probeProject
	}

	return joinIdentity(project, principal)
}

// azureRegistrationIdentity decodes the home-tenant ARM token into the display
// principal. Best-effort: any error => "". The caller bounds ctx.
func azureRegistrationIdentity(ctx context.Context, cred azcore.TokenCredential, scope string) string {
	id, err := azurehardening.NewIdentityProber(azurehardening.IdentityConfig{ //nolint:exhaustruct // Credential+Scope only.
		Credential: cred,
		Scope:      scope,
	}).
		Probe(ctx)
	if err != nil {
		return ""
	}

	return id.Principal
}

// fileExists reports whether path exists (file or directory). Shell I/O.
func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

// awsDefaultProfileFileHasCreds reports whether the AWS shared-config "default"
// profile declares credential-bearing fields (so a default SSO /
// credential_process / role profile with no env selector counts as explicit).
// It loads the profile with the AWS SDK's own shared-config parser, so all
// accepted syntax ([profile default] aliasing, inline comments, ':'/'=', key
// casing) is handled; a missing/unparseable default profile means "no creds".
// Shell I/O; the classification is the pure sharedConfigHasCreds.
func awsDefaultProfileFileHasCreds() bool {
	sc, err := awsconfig.LoadSharedConfigProfile(context.Background(), "default")
	if err != nil {
		return false
	}

	return sharedConfigHasCreds(sc)
}

// homeDirOrEmpty returns the user's home dir, or "" if it can't be resolved (the
// explicit helpers treat "" as "no home-based signal"). Shell I/O.
func homeDirOrEmpty() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return h
}
