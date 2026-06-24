package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestPolicyEvaluator_AllowedReturnsTrueOnAllowedDecision(t *testing.T) {
	t.Parallel()
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, _ *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			return &iam.SimulateCustomPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{{
					EvalActionName: aws.String("s3:ListBuckets"),
					EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
				}},
			}, nil
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	ok, err := eval.AllowedAll(t.Context(), []string{"s3:ListBuckets"})
	if err != nil {
		t.Fatalf("AllowedAll: %v", err)
	}
	if !ok {
		t.Errorf("AllowedAll = false, want true")
	}
}

func TestPolicyEvaluator_AllowedReturnsFalseOnImplicitDeny(t *testing.T) {
	t.Parallel()
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, _ *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			return &iam.SimulateCustomPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{{
					EvalDecision: iamtypes.PolicyEvaluationDecisionTypeImplicitDeny,
				}},
			}, nil
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	ok, err := eval.AllowedAll(t.Context(), []string{"s3:DeleteBucket"})
	if err != nil {
		t.Fatalf("AllowedAll: %v", err)
	}
	if ok {
		t.Errorf("AllowedAll = true, want false")
	}
	ok2, _ := eval.AllowedAll(t.Context(), []string{"s3:DeleteBucket"})
	if ok2 {
		t.Errorf("cached deny = true, want false")
	}
}

func TestPolicyEvaluator_CachesResult(t *testing.T) {
	t.Parallel()
	calls := 0
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, _ *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			calls++
			return &iam.SimulateCustomPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{{
					EvalDecision: iamtypes.PolicyEvaluationDecisionTypeAllowed,
				}},
			}, nil
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	_, _ = eval.AllowedAll(t.Context(), []string{"s3:ListBuckets"})
	_, _ = eval.AllowedAll(t.Context(), []string{"s3:ListBuckets"})
	if calls != 1 {
		t.Errorf("SimulateCustomPolicy called %d times, want 1", calls)
	}
}

func TestPolicyEvaluator_APIErrorReturnsErrPolicyEvalFailed(t *testing.T) {
	t.Parallel()
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, _ *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			return nil, errors.New("throttled")
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	_, err := eval.AllowedAll(t.Context(), []string{"s3:ListBuckets"})
	if !errors.Is(err, ErrPolicyEvalFailed) {
		t.Errorf("err = %v, want ErrPolicyEvalFailed", err)
	}
}

func TestPolicyEvaluator_EmptyResultReturnsErrPolicyEvalFailed(t *testing.T) {
	t.Parallel()
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, _ *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			return &iam.SimulateCustomPolicyOutput{EvaluationResults: nil}, nil
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	_, err := eval.AllowedAll(t.Context(), []string{"s3:ListBuckets"})
	if !errors.Is(err, ErrPolicyEvalFailed) {
		t.Errorf("err = %v, want ErrPolicyEvalFailed", err)
	}
}

func TestPolicyEvaluator_AllowedAll_allAllowed(t *testing.T) {
	t.Parallel()
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, _ *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			return &iam.SimulateCustomPolicyOutput{EvaluationResults: []iamtypes.EvaluationResult{{
				EvalDecision: iamtypes.PolicyEvaluationDecisionTypeAllowed,
			}}}, nil
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	ok, err := eval.AllowedAll(t.Context(), []string{"s3:ListBucket", "s3:GetObject"})
	if err != nil || !ok {
		t.Errorf("AllowedAll = %v,%v want true,nil", ok, err)
	}
}

func TestPolicyEvaluator_AllowedAll_oneDeniedShortCircuits(t *testing.T) {
	t.Parallel()
	calls := 0
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, in *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			calls++
			dec := iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
			if in.ActionNames[0] == "s3:ListBucket" {
				dec = iamtypes.PolicyEvaluationDecisionTypeAllowed
			}
			return &iam.SimulateCustomPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{{EvalDecision: dec}},
			}, nil
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	// Denied action first: AllowedAll must stop after the first deny.
	ok, err := eval.AllowedAll(t.Context(), []string{"s3:GetObjectAcl", "s3:ListBucket"})
	if err != nil || ok {
		t.Errorf("AllowedAll = %v,%v want false,nil", ok, err)
	}
	if calls != 1 {
		t.Errorf("evaluated %d actions, want 1 (short-circuit on first deny)", calls)
	}
}

func TestPolicyEvaluator_AllowedAll_propagatesError(t *testing.T) {
	t.Parallel()
	api := &simulateAPIMock{
		SimulateCustomPolicyFunc: func(
			_ context.Context, _ *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options),
		) (*iam.SimulateCustomPolicyOutput, error) {
			return nil, errors.New("throttled")
		},
	}
	eval := NewPolicyEvaluator("{}", "v1", api, 64)
	if _, err := eval.AllowedAll(t.Context(), []string{"s3:ListBucket"}); !errors.Is(err, ErrPolicyEvalFailed) {
		t.Errorf("err = %v, want ErrPolicyEvalFailed", err)
	}
}
