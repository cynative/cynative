package aws_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	awsh "github.com/cynative/cynative/internal/auth/aws"
)

// fakeIAMAPI is a minimal stand-in for awsh.iamAPI (which is unexported, so
// we can't reference it directly here — we just satisfy the structural shape
// by name).
type fakeIAMAPI struct {
	getPolicy        func(ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	getPolicyVersion func(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

func (f *fakeIAMAPI) GetPolicy(
	ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options),
) (*iam.GetPolicyOutput, error) {
	return f.getPolicy(ctx, in, opts...)
}

func (f *fakeIAMAPI) GetPolicyVersion(
	ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options),
) (*iam.GetPolicyVersionOutput, error) {
	return f.getPolicyVersion(ctx, in, opts...)
}

func TestFetchPolicyDocument(t *testing.T) {
	t.Parallel()
	rawDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`
	api := &fakeIAMAPI{
		getPolicy: func(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v3")},
			}, nil
		},
		getPolicyVersion: func(
			_ context.Context, _ *iam.GetPolicyVersionInput, _ ...func(*iam.Options),
		) (*iam.GetPolicyVersionOutput, error) {
			encoded := url.QueryEscape(rawDoc)
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(encoded)},
			}, nil
		},
	}
	doc, version, err := awsh.FetchPolicyDocument(t.Context(), api, "arn:aws:iam::aws:policy/SecurityAudit")
	if err != nil {
		t.Fatalf("FetchPolicyDocument: %v", err)
	}
	if version != "v3" {
		t.Errorf("version = %q, want v3", version)
	}
	if doc != rawDoc {
		t.Errorf("doc mismatch:\n got: %s\nwant: %s", doc, rawDoc)
	}
}

func TestFetchPolicyDocument_GetPolicyFails(t *testing.T) {
	t.Parallel()
	api := &fakeIAMAPI{
		getPolicy: func(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return nil, errors.New("forbidden")
		},
	}
	_, _, err := awsh.FetchPolicyDocument(t.Context(), api, "arn:aws:iam::aws:policy/X")
	if err == nil {
		t.Errorf("expected error from GetPolicy failure")
	}
}

func TestFetchPolicyDocument_EmptyPolicyResponse(t *testing.T) {
	t.Parallel()
	api := &fakeIAMAPI{
		getPolicy: func(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{Policy: nil}, nil
		},
	}
	_, _, err := awsh.FetchPolicyDocument(t.Context(), api, "arn:aws:iam::aws:policy/X")
	if err == nil {
		t.Errorf("expected error from empty Policy")
	}
}

func TestFetchPolicyDocument_GetPolicyVersionFails(t *testing.T) {
	t.Parallel()
	api := &fakeIAMAPI{
		getPolicy: func(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersion: func(
			_ context.Context, _ *iam.GetPolicyVersionInput, _ ...func(*iam.Options),
		) (*iam.GetPolicyVersionOutput, error) {
			return nil, errors.New("throttled")
		},
	}
	_, _, err := awsh.FetchPolicyDocument(t.Context(), api, "arn:aws:iam::aws:policy/X")
	if err == nil {
		t.Errorf("expected error from GetPolicyVersion failure")
	}
}

func TestFetchPolicyDocument_EmptyVersionResponse(t *testing.T) {
	t.Parallel()
	api := &fakeIAMAPI{
		getPolicy: func(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersion: func(
			_ context.Context, _ *iam.GetPolicyVersionInput, _ ...func(*iam.Options),
		) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{PolicyVersion: nil}, nil
		},
	}
	_, _, err := awsh.FetchPolicyDocument(t.Context(), api, "arn:aws:iam::aws:policy/X")
	if err == nil {
		t.Errorf("expected error from empty PolicyVersion")
	}
}

func TestFetchPolicyDocument_MalformedURLDoc(t *testing.T) {
	t.Parallel()
	api := &fakeIAMAPI{
		getPolicy: func(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersion: func(
			_ context.Context, _ *iam.GetPolicyVersionInput, _ ...func(*iam.Options),
		) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String("%ZZ")},
			}, nil
		},
	}
	_, _, err := awsh.FetchPolicyDocument(t.Context(), api, "arn:aws:iam::aws:policy/X")
	if err == nil {
		t.Errorf("expected error from malformed URL-encoded document")
	}
}
