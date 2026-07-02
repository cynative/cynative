package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const lazyTestPolicyARN = "arn:aws:iam::aws:policy/SecurityAudit"

// iamFullAPIMock satisfies iamFullAPI (iamAPI + simulateAPI) for tests.
// Only the two policy-fetch methods are needed for LazyResolve; SimulateCustomPolicy
// is present to satisfy the interface but not called during construction.
type iamFullAPIMock struct {
	iamAPIMock
	simulateAPIMock
}

func newTestLazyDeps(t *testing.T, iamMock iamFullAPI) LazyDeps {
	t.Helper()
	return LazyDeps{
		PolicyARN:       lazyTestPolicyARN,
		IAM:             iamMock,
		Archive:         &fakeArchive{models: nil, err: ErrUnsupportedService}, // not called during construction.
		ServiceRef:      &fakeSRGetter{model: nil},
		IAMDataset:      &fakeDSLookuper{actions: nil, gotSDK: nil},
		PolicyCacheSize: 16,
	}
}

func TestLazyResolve_succeeds(t *testing.T) {
	t.Parallel()
	iamMock := &iamFullAPIMock{ //nolint:exhaustruct // simulateAPIMock not needed here
		iamAPIMock: *newIAMMockWithPolicy(t, lazyTestPolicyARN),
	}

	actionProvider, err := LazyResolve(t.Context(), newTestLazyDeps(t, iamMock))
	if err != nil {
		t.Fatalf("LazyResolve: %v", err)
	}
	if actionProvider == nil {
		t.Error("action provider nil")
	}
}

func TestLazyResolve_PolicyError_returnsNotReady(t *testing.T) {
	t.Parallel()
	cause := errors.New("no such policy")
	iamMock := &iamFullAPIMock{ //nolint:exhaustruct // simulateAPIMock not needed here
		iamAPIMock: iamAPIMock{ //nolint:exhaustruct // only GetPolicy is exercised
			GetPolicyFunc: func(
				_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options),
			) (*iam.GetPolicyOutput, error) {
				return nil, cause
			},
		},
	}

	_, err := LazyResolve(t.Context(), newTestLazyDeps(t, iamMock))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "aws_hardening: policy fetch") {
		t.Errorf("policy-fetch step prefix missing: %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Errorf("error does not wrap injected cause: %v", err)
	}
}

// newIAMMockWithPolicy responds to GetPolicy + GetPolicyVersion with a minimal
// valid policy document.
func newIAMMockWithPolicy(t *testing.T, policyARN string) *iamAPIMock {
	t.Helper()
	// FetchPolicyDocument URL-decodes the Document field, so plain JSON is fine.
	const policyDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	return &iamAPIMock{ //nolint:exhaustruct // only the two used methods need stubs
		GetPolicyFunc: func(
			_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options),
		) (*iam.GetPolicyOutput, error) {
			if aws.ToString(in.PolicyArn) != policyARN {
				t.Errorf("GetPolicy arn = %q, want %q", aws.ToString(in.PolicyArn), policyARN)
			}
			return &iam.GetPolicyOutput{ //nolint:exhaustruct // AWS SDK type; only relevant fields set.
				Policy: &iamtypes.Policy{ //nolint:exhaustruct // AWS SDK type; only relevant fields set.
					Arn:              aws.String(policyARN),
					DefaultVersionId: aws.String("v1"),
				},
			}, nil
		},
		GetPolicyVersionFunc: func(
			_ context.Context, _ *iam.GetPolicyVersionInput, _ ...func(*iam.Options),
		) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{ //nolint:exhaustruct // AWS SDK type; only relevant fields set.
				PolicyVersion: &iamtypes.PolicyVersion{ //nolint:exhaustruct // AWS SDK type; only relevant fields set.
					Document:  aws.String(policyDoc),
					VersionId: aws.String("v1"),
				},
			}, nil
		},
	}
}
