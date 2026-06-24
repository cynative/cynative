package aws

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

//go:generate go tool moq -out iam_mock_test.go . iamAPI

// iamAPI is the subset of *iam.Client used at provider construction to fetch
// the configured policy doc.
type iamAPI interface {
	GetPolicy(
		ctx context.Context,
		in *iam.GetPolicyInput,
		opts ...func(*iam.Options),
	) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(
		ctx context.Context,
		in *iam.GetPolicyVersionInput,
		opts ...func(*iam.Options),
	) (*iam.GetPolicyVersionOutput, error)
}

// FetchPolicyDocument resolves arn to (URL-decoded PolicyDocument JSON, version ID).
// Two calls: GetPolicy (to find the default version) + GetPolicyVersion.
func FetchPolicyDocument(ctx context.Context, api iamAPI, arn string) (string, string, error) {
	pol, err := api.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return "", "", fmt.Errorf("get policy %s: %w", arn, err)
	}
	if pol.Policy == nil || pol.Policy.DefaultVersionId == nil {
		return "", "", fmt.Errorf("get policy %s: empty response", arn)
	}
	version := aws.ToString(pol.Policy.DefaultVersionId)

	ver, err := api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn),
		VersionId: aws.String(version),
	})
	if err != nil {
		return "", "", fmt.Errorf("get policy version %s/%s: %w", arn, version, err)
	}
	if ver.PolicyVersion == nil || ver.PolicyVersion.Document == nil {
		return "", "", fmt.Errorf("get policy version %s/%s: empty response", arn, version)
	}
	raw := aws.ToString(ver.PolicyVersion.Document)
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", "", fmt.Errorf("decode policy document: %w", err)
	}
	return decoded, version, nil
}
