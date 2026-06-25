package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	lru "github.com/hashicorp/golang-lru/v2"
)

//go:generate go tool moq -out simulate_mock_test.go . simulateAPI

// ErrPolicyEvalFailed indicates the policy evaluation API call itself failed
// (throttled, network, AWS-side error). Distinct from a "denied" decision.
var ErrPolicyEvalFailed = errors.New("aws_hardening: policy evaluation unavailable")

// simulateAPI is the subset of *iam.Client we depend on for evaluation.
// Mocked in tests via moq.
type simulateAPI interface {
	SimulateCustomPolicy(
		ctx context.Context,
		in *iam.SimulateCustomPolicyInput,
		opts ...func(*iam.Options),
	) (*iam.SimulateCustomPolicyOutput, error)
}

// PolicyEvaluator answers AllowedAll(actions) by calling iam:SimulateCustomPolicy
// with the configured policy doc, caching results in an LRU keyed by
// (policyVersion, action) so identical questions reuse the same decision.
type PolicyEvaluator struct {
	policyDoc     string
	policyVersion string
	api           simulateAPI
	cache         *lru.Cache[string, bool]
}

// NewPolicyEvaluator constructs an evaluator. policyDoc is the URL-decoded
// IAM PolicyDocument JSON; policyVersion is the policy version ID (used as
// the cache key prefix so policy edits don't poison the cache).
func NewPolicyEvaluator(policyDoc, policyVersion string, api simulateAPI, cacheSize int) *PolicyEvaluator {
	cache, _ := lru.New[string, bool](cacheSize) // err only on size <= 0; caller's responsibility.
	return &PolicyEvaluator{
		policyDoc:     policyDoc,
		policyVersion: policyVersion,
		api:           api,
		cache:         cache,
	}
}

// AllowedAll returns true only if every action is permitted. It short-circuits
// on the first denial and propagates the first evaluation error. An empty
// action list returns true (the caller guarantees a non-empty set; the
// resolver's SourceNone path handles "nothing to check").
func (e *PolicyEvaluator) AllowedAll(ctx context.Context, actions []string) (bool, error) {
	for _, action := range actions {
		key := e.policyVersion + "|" + action
		if v, ok := e.cache.Get(key); ok {
			if !v {
				return false, nil
			}
			continue
		}
		// The resource ARN and request context are omitted from
		// SimulateCustomPolicy, so the resource defaults to "*": exact for
		// action-level wildcard policies (the default SecurityAudit), but
		// action-name-only otherwise. A configured policy whose read-only intent
		// relies on resource scoping, conditions, or explicit Deny on specific
		// resources is enforced AWS-side for assumed-role identities (scoped
		// credential), but for IAM-user/root — which sign with base credentials —
		// only the action name is checked here (a known limitation; see docs/connectors/aws.md, Limitations).
		out, err := e.api.SimulateCustomPolicy(ctx, &iam.SimulateCustomPolicyInput{
			PolicyInputList: []string{e.policyDoc},
			ActionNames:     []string{action},
		})
		if err != nil {
			return false, fmt.Errorf("%w: %w", ErrPolicyEvalFailed, err)
		}
		if len(out.EvaluationResults) == 0 {
			return false, fmt.Errorf("%w: empty evaluation result", ErrPolicyEvalFailed)
		}
		allowed := out.EvaluationResults[0].EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed
		e.cache.Add(key, allowed)
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}
