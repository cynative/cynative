package auth

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	awshardening "github.com/cynative/cynative/internal/auth/aws"
)

// validateAWSPolicy confirms the configured IAM policy is fetchable and that the
// caller can invoke iam:SimulateCustomPolicy — the permission the request-time
// action gate depends on. Shell: real IAM client.
func validateAWSPolicy(ctx context.Context, cfg aws.Config, policyARN string) error {
	cfg.Region = resolveRegion(cfg.Region)
	client := iam.NewFromConfig(cfg)
	doc, ver, err := awshardening.FetchPolicyDocument(ctx, client, policyARN)
	if err != nil {
		return err
	}
	// Confirm the caller holds iam:SimulateCustomPolicy — the permission the
	// request-time action gate depends on; a benign action whose allow/deny
	// verdict is irrelevant (only an API-call error fails validation).
	eval := awshardening.NewPolicyEvaluator(doc, ver, client, 1)
	if _, serr := eval.AllowedAll(ctx, []string{"iam:GetUser"}); serr != nil {
		return serr
	}

	return nil
}

// buildHardenedAWSProvider constructs the hardened *awsProvider with all AWS
// I/O deferred to first use. The provider's doLazyResolve closure captures
// pre-built dependency clients (cheap, no I/O) and triggers LazyResolve on
// the first InjectAuth / AuthorizeAction. Credential scoping was resolved
// eagerly at registration (resolveScopeAWS); the pre-built scoped chain is
// passed in and threaded straight through to LazyResolve via LazyDeps.Credentials.
func buildHardenedAWSProvider(
	cfg aws.Config, hardeningCfg AWSHardeningConfig, scoped aws.CredentialsProvider,
) *awsProvider {
	// IAM is partition-global; the AWS SDK still requires a region for
	// endpoint resolution. Default to us-east-1 (resolveRegion's defaultRegion)
	// when the user has no region configured (env, profile, IMDS) — this only
	// affects the global control-plane clients here, never the per-tool request
	// region claim.
	cfg.Region = resolveRegion(cfg.Region)

	iamClient := iam.NewFromConfig(cfg)
	httpClient := &http.Client{Timeout: smithyHTTPTimeout} //nolint:exhaustruct // defaults are fine.
	archive := awshardening.NewModelArchive(awshardening.ModelArchiveConfig{
		Config:  hardeningCfg.Config,
		Fetcher: awshardening.NewModelArchiveFetcher(httpClient, awshardening.DefaultModelArchiveURL),
	})
	serviceRefReg := awshardening.NewServiceRefRegistry(awshardening.ServiceRefRegistryConfig{
		Config:  hardeningCfg.Config,
		Fetcher: awshardening.NewServiceRefFetcher(httpClient, awshardening.DefaultServiceRefTemplate),
	})
	iamDatasetReg := awshardening.NewIAMDatasetRegistry(awshardening.IAMDatasetRegistryConfig{
		Config:  hardeningCfg.Config,
		Fetcher: awshardening.NewIAMDatasetFetcher(httpClient, awshardening.DefaultIAMDatasetURL),
	})

	deps := awshardening.LazyDeps{
		PolicyARN:       hardeningCfg.PolicyARN,
		IAM:             iamClient,
		Archive:         archive,
		ServiceRef:      serviceRefReg,
		IAMDataset:      iamDatasetReg,
		Credentials:     scoped,
		PolicyCacheSize: policyCacheSize,
	}

	// Build the provider with a nil closure first, then assign one that
	// captures p so it can populate the provider's fields on first call.
	p := newAWSProvider(cfg, nil)
	p.doLazyResolve = func(ctx context.Context) error {
		res, err := awshardening.LazyResolve(ctx, deps)
		if err != nil {
			return err
		}
		p.cfg.Credentials = res.Credentials
		p.actionProvider = res.ActionProvider
		return nil
	}
	return p
}
