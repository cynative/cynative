package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// iamFullAPI combines the iamAPI and simulateAPI subsets of *iam.Client
// required for a full provider initialization: policy-document fetch (GetPolicy
// + GetPolicyVersion) and action evaluation (SimulateCustomPolicy).
type iamFullAPI interface {
	iamAPI
	simulateAPI
}

// LazyDeps carries everything LazyResolve still needs after the eager scope
// resolution at registration: the IAM policy fetch + action-provider build. The
// caller ARN was resolved at registration and the scoped credential chain was built
// eagerly (resolveScope); LazyResolve just threads the pre-built chain through.
type LazyDeps struct {
	PolicyARN       string
	IAM             iamFullAPI
	Archive         ModelResolver
	ServiceRef      serviceRefGetter
	IAMDataset      iamDatasetLookuper
	Credentials     aws.CredentialsProvider // pre-built aws.NewCredentialsCache(ScopedProvider).
	PolicyCacheSize int
}

// LazyResult is what LazyResolve hands back on success.
type LazyResult struct {
	ActionProvider *Provider
	Credentials    aws.CredentialsProvider // wrapped via aws.NewCredentialsCache(ScopedProvider).
}

// LazyResolve performs the still-deferred AWS init: fetch the IAM policy and build
// the action provider. Identity and credential scoping were resolved eagerly at
// registration; the pre-built scoped chain is passed straight through. It no longer
// calls sts:GetCallerIdentity or builds a ScopedProvider, and emits no steady-state
// posture line (the startup inventory is the source of truth).
func LazyResolve(ctx context.Context, deps LazyDeps) (*LazyResult, error) {
	policyDoc, policyVersion, err := FetchPolicyDocument(ctx, deps.IAM, deps.PolicyARN)
	if err != nil {
		return nil, cloudauth.NotReady("aws_hardening", "policy fetch", err)
	}

	evaluator := NewPolicyEvaluator(policyDoc, policyVersion, deps.IAM, deps.PolicyCacheSize)
	resolver := NewActionResolver(deps.ServiceRef, deps.IAMDataset)
	actionProvider := NewProvider(deps.Archive, resolver, evaluator, deps.PolicyARN)

	return &LazyResult{ActionProvider: actionProvider, Credentials: deps.Credentials}, nil
}
