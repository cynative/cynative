package aws

import (
	"context"

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
// resolution at registration: the IAM policy fetch + action-provider build.
// Identity and the scoped credential chain were resolved eagerly at
// registration (resolveScope) and assigned at provider construction.
type LazyDeps struct {
	PolicyARN       string
	IAM             iamFullAPI
	Archive         ModelResolver
	ServiceRef      serviceRefGetter
	IAMDataset      iamDatasetLookuper
	PolicyCacheSize int
}

// LazyResolve performs the still-deferred AWS init: fetch the IAM policy and
// build the action provider. It emits no steady-state posture line (the
// startup inventory is the source of truth).
func LazyResolve(ctx context.Context, deps LazyDeps) (*Provider, error) {
	policyDoc, policyVersion, err := FetchPolicyDocument(ctx, deps.IAM, deps.PolicyARN)
	if err != nil {
		return nil, cloudauth.NotReady("aws_hardening", "policy fetch", err)
	}

	evaluator := NewPolicyEvaluator(policyDoc, policyVersion, deps.IAM, deps.PolicyCacheSize)
	resolver := NewActionResolver(deps.ServiceRef, deps.IAMDataset)

	return NewProvider(deps.Archive, resolver, evaluator, deps.PolicyARN), nil
}
