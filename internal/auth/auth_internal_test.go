package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	"github.com/aws/aws-sdk-go-v2/aws"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	"golang.org/x/oauth2"
	container "google.golang.org/api/container/v1"
	"google.golang.org/api/option"

	"github.com/cynative/cynative/internal/auth/authtest"
	awshardening "github.com/cynative/cynative/internal/auth/aws"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

func fakeAWSCreds(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Source:          "test",
	}, nil
}

// mockCredential returns a moq mock of azcore.TokenCredential whose GetToken
// yields the given token and error.
func mockCredential(token azcore.AccessToken, err error) *tokenCredentialMock {
	return &tokenCredentialMock{
		GetTokenFunc: func(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
			return token, err
		},
	}
}

// mockTokenSource returns a moq mock of oauth2.TokenSource whose Token yields
// the given token and error.
func mockTokenSource(token *oauth2.Token, err error) *tokenSourceMock {
	return &tokenSourceMock{
		TokenFunc: func() (*oauth2.Token, error) {
			return token, err
		},
	}
}

func TestTokenWithContext_ReturnsToken(t *testing.T) {
	t.Parallel()

	ts := mockTokenSource(&oauth2.Token{AccessToken: "abc"}, nil) //nolint:exhaustruct // only AccessToken.

	tok, err := tokenWithContext(context.Background(), ts)
	if err != nil {
		t.Fatalf("tokenWithContext: %v", err)
	}
	if tok.AccessToken != "abc" {
		t.Fatalf("AccessToken = %q, want abc", tok.AccessToken)
	}
}

func TestTokenWithContext_ReturnsWhenContextCancelled(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	// A token source whose refresh stalls (no context to cancel it): only the
	// caller's context can end the wait.
	ts := &tokenSourceMock{TokenFunc: func() (*oauth2.Token, error) {
		<-release

		return &oauth2.Token{AccessToken: "late"}, nil //nolint:exhaustruct // only AccessToken.
	}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tok, err := tokenWithContext(ctx, ts)
	if err == nil {
		t.Fatal("expected a context error from the stalled token refresh, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if tok != nil {
		t.Fatalf("want nil token on cancellation, got %+v", tok)
	}
}

func TestGitHubProvider_NameAndDescription(t *testing.T) {
	t.Parallel()

	p := &githubProvider{token: "test-token"}

	if p.Name() != "github" {
		t.Errorf("expected name 'github', got %q", p.Name())
	}

	if !strings.Contains(p.Description(), "GitHub") {
		t.Errorf("expected description to mention GitHub, got %q", p.Description())
	}
}

func TestGitHubProvider_InjectAuth(t *testing.T) {
	t.Parallel()

	p := &githubProvider{token: "ghp_test123"}

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://api.github.com/repos/test/test", nil,
	)

	if err := p.InjectAuth(req, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer ghp_test123" {
		t.Errorf("expected 'Bearer ghp_test123', got %q", got)
	}

	// X-Github-Api-Version is stripped so GitHub uses its current default version,
	// which the live-fetched OpenAPI spec (main branch) describes.
	if got := req.Header.Get("X-Github-Api-Version"); got != "" {
		t.Errorf("expected X-Github-Api-Version absent (stripped), got %q", got)
	}
}

func TestGitHubProvider_InjectAuth_StripsModelApiVersion(t *testing.T) {
	t.Parallel()

	p := &githubProvider{token: "ghp_test123"}

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://api.github.com/repos/test/test", nil,
	)
	req.Header.Set("X-Github-Api-Version", "2099-01-01") // model-supplied — must be removed.

	if err := p.InjectAuth(req, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("X-Github-Api-Version"); got != "" {
		t.Errorf("expected X-Github-Api-Version stripped, got %q", got)
	}
}

func TestAWSProvider_Name(t *testing.T) {
	t.Parallel()

	p := &awsProvider{}
	if p.Name() != "aws" {
		t.Errorf("expected name %q, got %q", "aws", p.Name())
	}
}

func TestAWSProvider_Description(t *testing.T) {
	t.Parallel()

	p := &awsProvider{}
	desc := p.Description()

	if !strings.Contains(desc, "AWS") {
		t.Errorf("expected description to contain 'AWS', got %q", desc)
	}

	if !strings.Contains(desc, "SigV4") {
		t.Errorf("expected description to contain 'SigV4', got %q", desc)
	}
}

func TestAWSProvider_InjectAuth_MissingService(t *testing.T) {
	t.Parallel()

	p := &awsProvider{
		lazyInit: lazyInit{doLazyResolve: func(_ context.Context) error { return nil }},
	} //nolint:exhaustruct // test struct
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://s3.us-east-1.amazonaws.com/bucket", nil,
	)

	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"region": "us-east-1"},
	})

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error when aws_auth.service is missing")
	}

	if !strings.Contains(err.Error(), "aws_auth.service is required") {
		t.Errorf("expected 'aws_auth.service is required' in error, got: %v", err)
	}
}

func TestAWSProvider_InjectAuth_InvalidJSON(t *testing.T) {
	t.Parallel()

	p := &awsProvider{
		lazyInit: lazyInit{doLazyResolve: func(_ context.Context) error { return nil }},
	} //nolint:exhaustruct // test struct
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://s3.us-east-1.amazonaws.com/bucket", nil,
	)

	err := p.InjectAuth(req, json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error from invalid JSON")
	}

	if !strings.Contains(err.Error(), "failed to parse aws_auth args") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestAWSProvider_InjectAuth_CredRetrieveError(t *testing.T) {
	t.Parallel()

	p := &awsProvider{ //nolint:exhaustruct // test struct
		cfg: aws.Config{
			Region: "us-east-1",
			Credentials: aws.CredentialsProviderFunc(
				func(_ context.Context) (aws.Credentials, error) {
					return aws.Credentials{}, errors.New("cred boom")
				},
			),
		},
		lazyInit: lazyInit{doLazyResolve: func(_ context.Context) error { return nil }}, //nolint:exhaustruct // test
	}
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "s3", "region": "us-east-1"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://s3.us-east-1.amazonaws.com/bucket", nil,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error from credential retrieval failure")
	}

	if !strings.Contains(err.Error(), "failed to retrieve AWS credentials") {
		t.Errorf("expected credential error, got: %v", err)
	}
}

func TestAWSProvider_InjectAuth_NilBody(t *testing.T) {
	t.Parallel()

	p := newAWSProvider(aws.Config{
		Region:      "us-west-2",
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
	}, func(_ context.Context) error { return nil })
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "s3", "region": "eu-west-1"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://s3.eu-west-1.amazonaws.com/bucket", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if auth := req.Header.Get("Authorization"); auth == "" {
		t.Error("expected Authorization header to be set")
	}

	if got := req.Header.Get("X-Amz-Content-Sha256"); got == "" {
		t.Error("expected X-Amz-Content-Sha256 header to be set")
	}
}

func TestAWSProvider_InjectAuth_WithBody(t *testing.T) {
	t.Parallel()

	p := newAWSProvider(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
	}, func(_ context.Context) error { return nil })
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "execute-api", "region": "us-east-1"},
	})
	body := strings.NewReader(`{"key":"value"}`)
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://example.execute-api.us-east-1.amazonaws.com/prod", body,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if auth := req.Header.Get("Authorization"); auth == "" {
		t.Error("expected Authorization header to be set")
	}

	// Body should still be readable after signing.
	readBack, _ := io.ReadAll(req.Body)
	if string(readBack) != `{"key":"value"}` {
		t.Errorf("body was not preserved after signing, got: %q", readBack)
	}
}

func TestAWSProvider_InjectAuth_BodyReadError(t *testing.T) {
	t.Parallel()

	p := &awsProvider{ //nolint:exhaustruct // test struct
		cfg: aws.Config{
			Region:      "us-east-1",
			Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
		},
		lazyInit: lazyInit{doLazyResolve: func(_ context.Context) error { return nil }}, //nolint:exhaustruct // test
	}
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "s3", "region": "us-east-1"},
	})

	failReader := io.NopCloser(
		iotest.ErrReader(errors.New("read boom")),
	)
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://s3.us-east-1.amazonaws.com/bucket", failReader,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error from body read failure")
	}

	if !strings.Contains(err.Error(), "failed to read request body for signing") {
		t.Errorf("expected body read error, got: %v", err)
	}
}

func TestAWSProvider_InjectAuth_SignError(t *testing.T) {
	t.Parallel()

	p := &awsProvider{ //nolint:exhaustruct // test struct
		cfg: aws.Config{
			Region:      "us-east-1",
			Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
		},
		signHTTP: func(
			_ context.Context,
			_ aws.Credentials,
			_ *http.Request,
			_, _, _ string,
			_ time.Time,
		) error {
			return errors.New("sign boom")
		},
		lazyInit: lazyInit{doLazyResolve: func(_ context.Context) error { return nil }}, //nolint:exhaustruct // test
	}
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "s3", "region": "us-east-1"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://s3.us-east-1.amazonaws.com/bucket", nil,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error from signing failure")
	}

	if !strings.Contains(err.Error(), "failed to sign AWS request") {
		t.Errorf("expected sign error, got: %v", err)
	}
}

// TestAWSProvider_InjectAuth_signsWithResolvedSigningName verifies that even
// when the model claims the endpoint prefix ("api.ecr"), the request is signed
// under the host's canonical SigV4 signing name ("ecr").
func TestAWSProvider_InjectAuth_signsWithResolvedSigningName(t *testing.T) {
	t.Parallel()
	p := newAWSProviderWithModels(t,
		[]*awshardening.ServiceModel{{EndpointPrefix: "api.ecr", SigningName: "ecr"}}, nil)
	p.cfg.Credentials = aws.CredentialsProviderFunc(fakeAWSCreds)
	var gotService string
	p.signHTTP = func(
		_ context.Context, _ aws.Credentials, _ *http.Request, _, service, _ string, _ time.Time,
	) error {
		gotService = service
		return nil
	}
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "api.ecr", "region": "us-east-1"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://api.ecr.us-east-1.amazonaws.com/", strings.NewReader("{}"),
	)
	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("InjectAuth: %v", err)
	}
	if gotService != "ecr" {
		t.Errorf("signed with service %q, want ecr (resolved signing name)", gotService)
	}
}

func TestAWSProvider_InjectAuth_RegionFallbackToConfig(t *testing.T) {
	t.Parallel()

	p := newAWSProvider(aws.Config{
		Region:      "ap-southeast-1",
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
	}, func(_ context.Context) error { return nil })
	// No region in aws_auth — signingRegion derives us-east-1 from the global host
	// (s3.amazonaws.com). The Authorization header is set.
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "s3"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://s3.amazonaws.com/bucket", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if auth := req.Header.Get("Authorization"); auth == "" {
		t.Error("expected Authorization header to be set")
	}
}

func TestAWSProvider_InjectAuth_RegionFallbackToDefault(t *testing.T) {
	t.Parallel()

	// No region in aws_auth or SDK config — signingRegion derives us-east-1 from
	// the global host (s3.amazonaws.com). The Authorization header is set.
	p := newAWSProvider(aws.Config{
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
	}, func(_ context.Context) error { return nil })
	rawArgs, _ := json.Marshal(map[string]any{
		"aws_auth": map[string]string{"service": "s3"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://s3.amazonaws.com/bucket", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if auth := req.Header.Get("Authorization"); auth == "" {
		t.Error("expected Authorization header to be set")
	}
}

func TestEKSProvider_Name(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}
	if p.Name() != "eks" {
		t.Errorf("expected name %q, got %q", "eks", p.Name())
	}
}

func TestEKSProvider_Description(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}
	desc := p.Description()

	if !strings.Contains(desc, "EKS") {
		t.Errorf("expected description to contain 'EKS', got %q", desc)
	}
}

func TestEKSProvider_InjectAuth_MissingCluster(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://kubernetes.default.svc/api/v1/pods", nil,
	)

	rawArgs, _ := json.Marshal(map[string]any{
		"eks_auth": map[string]string{"region": "us-east-1"},
	})

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error when eks_auth.cluster_name is missing")
	}

	if !strings.Contains(err.Error(), "eks_auth.cluster_name is required") {
		t.Errorf("expected 'eks_auth.cluster_name is required' in error, got: %v", err)
	}
}

func TestEKSProvider_InjectAuth_InvalidJSON(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://kubernetes.default.svc", nil,
	)

	err := p.InjectAuth(req, json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error from invalid JSON")
	}

	if !strings.Contains(err.Error(), "failed to parse eks_auth args") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestEKSProvider_InjectAuth_CredRetrieveError(t *testing.T) {
	t.Parallel()

	p := &eksProvider{
		cfg: aws.Config{
			Region: "us-east-1",
			Credentials: aws.CredentialsProviderFunc(
				func(_ context.Context) (aws.Credentials, error) {
					return aws.Credentials{}, errors.New("cred boom")
				},
			),
		},
	}
	rawArgs, _ := json.Marshal(map[string]any{
		"eks_auth": map[string]string{"cluster_name": "test-cluster", "region": "us-east-1"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://kubernetes.default.svc", nil,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error from credential retrieval failure")
	}

	if !strings.Contains(err.Error(), "failed to retrieve AWS credentials") {
		t.Errorf("expected credential error, got: %v", err)
	}
}

func TestEKSProvider_InjectAuth_Success(t *testing.T) {
	t.Parallel()

	p := newEKSProvider(aws.Config{
		Region:      "us-west-2",
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
	})
	rawArgs, _ := json.Marshal(map[string]any{
		"eks_auth": map[string]string{"cluster_name": "test-cluster", "region": "eu-west-1"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://kubernetes.default.svc/api/v1/pods", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Error("expected Authorization header to be set")
	}

	if !strings.HasPrefix(auth, "Bearer k8s-aws-v1.") {
		t.Errorf("expected Bearer token starting with k8s-aws-v1., got %q", auth)
	}
}

func TestEKSProvider_InjectAuth_NilEKSAuthField(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://kubernetes.default.svc", nil,
	)

	// Valid JSON but no "eks_auth" key → parsed.EKSAuth is nil → clusterName is "".
	rawArgs, _ := json.Marshal(map[string]any{})

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error when eks_auth field is absent")
	}

	if !strings.Contains(err.Error(), "eks_auth.cluster_name is required") {
		t.Errorf("expected 'eks_auth.cluster_name is required' in error, got: %v", err)
	}
}

func TestEKSProvider_InjectAuth_RegionFallbackToDefault(t *testing.T) {
	t.Parallel()

	// No region in cached config.
	p := newEKSProvider(aws.Config{
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
	})
	// No region in eks_auth either → should fall back to "us-east-1".
	rawArgs, _ := json.Marshal(map[string]any{
		"eks_auth": map[string]string{"cluster_name": "test-cluster"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://kubernetes.default.svc/api/v1/pods", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer k8s-aws-v1.") {
		t.Errorf("expected Bearer token starting with k8s-aws-v1., got %q", auth)
	}
}

type failSerializeMiddleware struct{}

func (failSerializeMiddleware) ID() string { return "FailSerialize" }

func (failSerializeMiddleware) HandleSerialize(
	_ context.Context,
	_ smithymiddleware.SerializeInput,
	_ smithymiddleware.SerializeHandler,
) (smithymiddleware.SerializeOutput, smithymiddleware.Metadata, error) {
	return smithymiddleware.SerializeOutput{}, smithymiddleware.Metadata{}, errors.New("forced serialization failure")
}

func TestDefaultEKSPresign_Error(t *testing.T) {
	t.Parallel()

	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
		APIOptions: []func(*smithymiddleware.Stack) error{
			func(stack *smithymiddleware.Stack) error {
				return stack.Serialize.Add(failSerializeMiddleware{}, smithymiddleware.Before)
			},
		},
	}

	_, err := defaultEKSPresign(context.Background(), cfg, "test-cluster")
	if err == nil {
		t.Fatal("expected error from broken middleware")
	}
}

func TestEKSProvider_InjectAuth_PresignError(t *testing.T) {
	t.Parallel()

	p := &eksProvider{
		cfg: aws.Config{
			Region:      "us-east-1",
			Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
		},
		presign: func(_ context.Context, _ aws.Config, _ string) (string, error) {
			return "", errors.New("presign boom")
		},
	}
	rawArgs, _ := json.Marshal(map[string]any{
		"eks_auth": map[string]string{"cluster_name": "test-cluster"},
	})
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://kubernetes.default.svc", nil,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error from presign failure")
	}

	if !strings.Contains(err.Error(), "failed to presign EKS token request") {
		t.Errorf("expected presign error, got: %v", err)
	}
}

// --- Inject function tests ---

func TestInject_MatchesProvider(t *testing.T) {
	t.Parallel()

	p := &githubProvider{token: "ghp_test123"}
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://api.github.com/repos/test/test", nil,
	)

	if err := Inject(req, "github", []Provider{p}, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer ghp_test123" {
		t.Errorf("expected 'Bearer ghp_test123', got %q", got)
	}
}

func TestInject_CaseInsensitive(t *testing.T) {
	t.Parallel()

	p := &githubProvider{token: "ghp_case"}
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://api.github.com/repos/test/test", nil,
	)

	if err := Inject(req, "GitHub", []Provider{p}, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer ghp_case" {
		t.Errorf("expected 'Bearer ghp_case', got %q", got)
	}
}

func TestInject_UnknownProvider(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://example.com", nil,
	)

	err := Inject(req, "nonexistent", nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}

	if !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("expected ErrUnknownProvider, got: %v", err)
	}
}

func TestInject_ProviderError(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://example.com", nil,
	)

	err := Inject(req, "failing", []Provider{&authtest.FailingProvider{}}, nil)
	if err == nil {
		t.Fatal("expected error from failing provider")
	}

	if !strings.Contains(err.Error(), "failed to inject auth for provider failing") {
		t.Errorf("expected inject error, got: %v", err)
	}
}

func TestInject_RejectsModelSuppliedCredentialHeaders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		seed func(r *http.Request)
	}{
		{"authorization header", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer bogus")
		}},
		{"proxy-authorization header", func(r *http.Request) {
			r.Header.Set("Proxy-Authorization", "Basic bogus")
		}},
		{"x-ms-authorization-auxiliary header", func(r *http.Request) {
			r.Header.Set("X-Ms-Authorization-Auxiliary", "Bearer aux")
		}},
		{"duplicate authorization with empty first value", func(r *http.Request) {
			r.Header.Add("Authorization", "")
			r.Header.Add("Authorization", "Bearer smuggled")
		}},
		{"empty-valued authorization still counts as present", func(r *http.Request) {
			r.Header.Add("Authorization", "")
		}},
		{"non-canonical header key set by direct map assignment", func(r *http.Request) {
			// Add canonicalizes, so assign the map directly to mimic a request
			// whose key Go would serialize verbatim ("authorization") yet a
			// canonical Values lookup would miss.
			r.Header["authorization"] = []string{"Bearer smuggled"}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &githubProvider{token: "ghp_never_injected"}
			req, _ := http.NewRequestWithContext(
				context.Background(), http.MethodGet,
				"https://api.github.com/repos/test/test", nil,
			)
			tc.seed(req)

			err := Inject(req, "github", []Provider{p}, nil)
			if !errors.Is(err, ErrModelSuppliedCredential) {
				t.Fatalf("Inject = %v, want ErrModelSuppliedCredential", err)
			}

			for _, v := range req.Header.Values("Authorization") {
				if strings.Contains(v, "ghp_never_injected") {
					t.Error("provider credential must not be injected on rejection")
				}
			}
		})
	}
}

// TestRejectModelSuppliedCredential_GitLabHeaders asserts that model-supplied
// Private-Token and Job-Token headers are rejected before credential injection.
func TestRejectModelSuppliedCredential_GitLabHeaders(t *testing.T) {
	t.Parallel()

	headers := map[string]string{
		"PRIVATE-TOKEN":                "smuggled",
		"JOB-TOKEN":                    "smuggled",
		"Private-Token":                "smuggled",
		"job-token":                    "smuggled",
		"Deploy-Token":                 "smuggled",                 // GitLab package/registry deploy token.
		"X-Gitlab-Static-Object-Token": "smuggled",                 // GitLab static-object credential.
		"Cookie":                       "_gitlab_session=smuggled", // GitLab session-cookie auth.
		// Underscore variants: Rack-style backends fold these onto the hyphenated HTTP_ vars.
		"Private_Token":                "smuggled",
		"Deploy_Token":                 "smuggled",
		"X_Gitlab_Static_Object_Token": "smuggled",
		// Rails authorization fallbacks (X-HTTP_AUTHORIZATION / X_HTTP_AUTHORIZATION).
		"X-HTTP_AUTHORIZATION": "Bearer smuggled",
		"X_HTTP_AUTHORIZATION": "Bearer smuggled",
	}
	for h, v := range headers {
		t.Run(h, func(t *testing.T) {
			t.Parallel()

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"https://gitlab.com/api/v4/user", nil)
			req.Header.Set(h, v)

			if err := rejectModelSuppliedCredential(req, "gitlab"); !errors.Is(err, ErrModelSuppliedCredential) {
				t.Fatalf("header %q: want ErrModelSuppliedCredential, got %v", h, err)
			}
		})
	}
}

func TestRejectModelSuppliedCredential_QueryParams(t *testing.T) {
	t.Parallel()

	for _, p := range []string{
		"private_token", "access_token", "job_token", "ACCESS_TOKEN", "feed_token", "rss_token",
		"private_token[]", "access_token[admin]", // Rack bracket forms expand to the base param.
	} {
		t.Run(p, func(t *testing.T) {
			t.Parallel()

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"https://gitlab.com/api/v4/user?"+p+"=smuggled", nil)

			if err := rejectModelSuppliedCredential(req, "gitlab"); !errors.Is(err, ErrModelSuppliedCredential) {
				t.Fatalf("query param %q: want ErrModelSuppliedCredential, got %v", p, err)
			}
		})
	}

	t.Run("clean query passes", func(t *testing.T) {
		t.Parallel()

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
			"https://gitlab.com/api/v4/projects?per_page=20", nil)

		if err := rejectModelSuppliedCredential(req, "gitlab"); err != nil {
			t.Fatalf("clean query must pass, got %v", err)
		}
	})

	// A ";"-separated query is rejected by Go's url.ParseQuery but honored by
	// GitLab/Rack, so it could hide a smuggled token; fail closed on the parse error.
	t.Run("semicolon query fails closed", func(t *testing.T) {
		t.Parallel()

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
			"https://gitlab.com/api/v4/projects?private_token=x;foo=1", nil)

		if err := rejectModelSuppliedCredential(req, "gitlab"); !errors.Is(err, ErrModelSuppliedCredential) {
			t.Fatalf("semicolon query must fail closed, got %v", err)
		}
	})
}

func TestInject_RejectsURLUserinfo(t *testing.T) {
	t.Parallel()

	p := &githubProvider{token: "ghp_never_injected"}
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://model:smuggled@api.github.com/repos/test/test", nil,
	)

	err := Inject(req, "github", []Provider{p}, nil)
	if !errors.Is(err, ErrModelSuppliedCredential) {
		t.Fatalf("Inject = %v, want ErrModelSuppliedCredential", err)
	}
}

// TestInject_MTLSProvidersRejectSeededHeader is the acceptance
// check: the two providers whose mTLS InjectAuth paths set no header must
// never let a model-supplied Authorization reach the wire. The gate fires
// before any provider code runs, so neither provider needs functional
// cluster config — registration under the right name is what is exercised.
func TestInject_MTLSProvidersRejectSeededHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		p    Provider
	}{
		{"kubernetes", newKubernetesProvider(resolvedCluster{mode: credMTLS, clientCert: "c", clientKey: "k"})},
		{"aks", newAKSProvider(&tokenCredentialMock{}, cloud.Configuration{})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req, _ := http.NewRequestWithContext(
				context.Background(), http.MethodGet,
				"https://10.0.0.1:6443/api/v1/namespaces/default/pods", nil,
			)
			req.Header.Set("Authorization", "Bearer model-smuggled")

			err := Inject(req, tc.name, []Provider{tc.p}, nil)
			if !errors.Is(err, ErrModelSuppliedCredential) {
				t.Fatalf("Inject(%s) = %v, want ErrModelSuppliedCredential", tc.name, err)
			}
		})
	}
}

// --- resolveRegion tests ---

func TestResolveRegion_FirstNonEmpty(t *testing.T) {
	t.Parallel()

	if got := resolveRegion("eu-west-1", "ap-southeast-1"); got != "eu-west-1" {
		t.Errorf("expected 'eu-west-1', got %q", got)
	}
}

func TestResolveRegion_FallsThrough(t *testing.T) {
	t.Parallel()

	if got := resolveRegion("", "ap-southeast-1"); got != "ap-southeast-1" {
		t.Errorf("expected 'ap-southeast-1', got %q", got)
	}
}

func TestResolveRegion_DefaultFallback(t *testing.T) {
	t.Parallel()

	if got := resolveRegion("", ""); got != defaultRegion {
		t.Errorf("expected %q, got %q", defaultRegion, got)
	}
}

// --- getPayloadHash tests ---

func TestGetPayloadHash_NilBody(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://example.com", nil,
	)

	hash, err := getPayloadHash(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash != emptyPayloadSHA256 {
		t.Errorf("expected empty payload hash, got %q", hash)
	}
}

func TestGetPayloadHash_WithBody(t *testing.T) {
	t.Parallel()

	body := strings.NewReader(`{"key":"value"}`)
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://example.com", body,
	)

	hash, err := getPayloadHash(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash == "" || hash == emptyPayloadSHA256 {
		t.Error("expected non-empty payload hash for body")
	}

	// Body must still be readable.
	readBack, _ := io.ReadAll(req.Body)
	if string(readBack) != `{"key":"value"}` {
		t.Errorf("body was not preserved after hashing, got: %q", readBack)
	}
}

func TestGetPayloadHash_ReadError(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://example.com",
		io.NopCloser(iotest.ErrReader(errors.New("read boom"))),
	)

	_, err := getPayloadHash(req)
	if err == nil {
		t.Fatal("expected error from body read failure")
	}

	if !strings.Contains(err.Error(), "failed to read request body for signing") {
		t.Errorf("expected body read error, got: %v", err)
	}
}

// --- GetCACertData tests ---

// caTestProvider implements both Provider and CACertProvider.
type caTestProvider struct {
	cert string
	err  error
}

func (p *caTestProvider) Name() string                                        { return "ca-test" }
func (p *caTestProvider) Description() string                                 { return "test" }
func (p *caTestProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }
func (p *caTestProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

func (p *caTestProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.cert, p.err
}

// assertCACertResult checks the result of GetCACertData against expected values.
func assertCACertResult(t *testing.T, got string, err error, wantCert string, wantErrIs error, wantErrText string) {
	t.Helper()

	if wantErrIs != nil {
		if !errors.Is(err, wantErrIs) {
			t.Fatalf("expected error %v, got: %v", wantErrIs, err)
		}

		return
	}

	if wantErrText != "" {
		if err == nil || !strings.Contains(err.Error(), wantErrText) {
			t.Fatalf("expected error containing %q, got: %v", wantErrText, err)
		}

		return
	}

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != wantCert {
		t.Errorf("expected cert %q, got: %q", wantCert, got)
	}
}

func TestGetCACertData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		provider    string
		providers   []Provider
		wantCert    string
		wantErrIs   error
		wantErrText string
	}{
		{
			name:      "provider with cert",
			provider:  "ca-test",
			providers: []Provider{&caTestProvider{cert: "dGVzdC1jZXJ0"}},
			wantCert:  "dGVzdC1jZXJ0",
		},
		{
			name:      "provider without CA cert",
			provider:  "failing",
			providers: []Provider{&authtest.FailingProvider{}},
			wantCert:  "",
		},
		{
			name:      "unknown provider",
			provider:  "nonexistent",
			providers: nil,
			wantErrIs: ErrUnknownProvider,
		},
		{
			name:      "empty name",
			provider:  "",
			providers: nil,
			wantCert:  "",
		},
		{
			name:      "case insensitive",
			provider:  "CA-TEST",
			providers: []Provider{&caTestProvider{cert: "abc"}},
			wantCert:  "abc",
		},
		{
			name:        "provider error",
			provider:    "ca-test",
			providers:   []Provider{&caTestProvider{err: errors.New("boom")}},
			wantErrText: "boom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetCACertData(context.Background(), tt.provider, tt.providers, nil)

			assertCACertResult(t, got, err, tt.wantCert, tt.wantErrIs, tt.wantErrText)
		})
	}
}

func TestGetClientCertData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		provider  string
		providers []Provider
		wantCert  string
		wantKey   string
		wantErrIs error
	}{
		{
			name:      "provider with cert",
			provider:  "aks",
			providers: []Provider{authtest.NewAKSCert("", "Y2VydC1kYXRh", "a2V5LWRhdGE=")},
			wantCert:  "Y2VydC1kYXRh",
			wantKey:   "a2V5LWRhdGE=",
		},
		{
			name:      "provider without client cert",
			provider:  "failing",
			providers: []Provider{&authtest.FailingProvider{}},
			wantCert:  "",
			wantKey:   "",
		},
		{
			name:      "unknown provider",
			provider:  "nonexistent",
			providers: nil,
			wantErrIs: ErrUnknownProvider,
		},
		{
			name:      "empty name",
			provider:  "",
			providers: nil,
			wantCert:  "",
			wantKey:   "",
		},
		{
			name:      "case insensitive",
			provider:  "AKS",
			providers: []Provider{authtest.NewAKSCert("", "Y2VydC1kYXRh", "a2V5LWRhdGE=")},
			wantCert:  "Y2VydC1kYXRh",
			wantKey:   "a2V5LWRhdGE=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotCert, gotKey, err := GetClientCertData(context.Background(), tt.provider, tt.providers, nil)

			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("expected error %v, got: %v", tt.wantErrIs, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotCert != tt.wantCert {
				t.Errorf("expected cert %q, got: %q", tt.wantCert, gotCert)
			}
			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got: %q", tt.wantKey, gotKey)
			}
		})
	}
}

// --- EKS CACertData programmatic resolution tests ---

func TestEKSProvider_CACertData_Success(t *testing.T) {
	t.Parallel()

	p := &eksProvider{
		cfg: aws.Config{Region: "us-east-1"},
		describeCluster: func(_ context.Context, _ aws.Config, name string) (clusterTLS, error) {
			if name != "test-cluster" {
				t.Errorf("expected cluster name 'test-cluster', got %q", name)
			}

			return clusterTLS{host: "h", caData: "dGVzdC1jYQ=="}, nil
		},
	}

	rawArgs := json.RawMessage(`{"eks_auth":{"cluster_name":"test-cluster","region":"eu-west-1"}}`)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "dGVzdC1jYQ==" {
		t.Errorf("expected cert data, got: %q", got)
	}
}

func TestEKSProvider_CACertData_APIError(t *testing.T) {
	t.Parallel()

	p := &eksProvider{
		cfg: aws.Config{Region: "us-east-1"},
		describeCluster: func(_ context.Context, _ aws.Config, _ string) (clusterTLS, error) {
			return clusterTLS{}, errors.New("describe boom")
		},
	}

	rawArgs := json.RawMessage(`{"eks_auth":{"cluster_name":"test-cluster"}}`)

	_, err := p.CACertData(context.Background(), rawArgs)
	if err == nil {
		t.Fatal("expected error from API failure")
	}

	if !strings.Contains(err.Error(), "describe boom") {
		t.Errorf("expected API error, got: %v", err)
	}
}

func TestEKSProvider_CACertData_NilArgs(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}

	got, err := p.CACertData(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "" {
		t.Errorf("expected empty, got: %q", got)
	}
}

func TestEKSProvider_CACertData_BadJSON(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}

	_, err := p.CACertData(context.Background(), json.RawMessage(`{bad json}`))
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}
}

func TestEKSProvider_CACertData_EmptyClusterName(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}

	rawArgs := json.RawMessage(`{"eks_auth":{"cluster_name":""}}`)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "" {
		t.Errorf("expected empty, got: %q", got)
	}
}

// --- CA cache tests ---

func TestEKSProvider_CACertData_CacheHit(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int64

	p := &eksProvider{
		cfg: aws.Config{Region: "us-east-1"},
		describeCluster: func(_ context.Context, _ aws.Config, _ string) (clusterTLS, error) {
			callCount.Add(1)

			return clusterTLS{host: "h", caData: "dGVzdC1jYQ=="}, nil
		},
	}

	rawArgs := json.RawMessage(`{"eks_auth":{"cluster_name":"test-cluster"}}`)

	// First call — should hit the API.
	got1, err1 := p.CACertData(context.Background(), rawArgs)
	if err1 != nil {
		t.Fatalf("first call: unexpected error: %v", err1)
	}

	if got1 != "dGVzdC1jYQ==" {
		t.Errorf("first call: expected cert data, got: %q", got1)
	}

	// Second call — should use cache, not the API.
	got2, err2 := p.CACertData(context.Background(), rawArgs)
	if err2 != nil {
		t.Fatalf("second call: unexpected error: %v", err2)
	}

	if got2 != got1 {
		t.Errorf("second call: expected same result, got: %q", got2)
	}

	if callCount.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", callCount.Load())
	}
}

func TestGKEProvider_CACertData_CacheHit(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int64

	p := &gkeProvider{
		tokenSource: mockTokenSource(&oauth2.Token{}, nil),
		getCluster: func(
			_ context.Context, _ oauth2.TokenSource, _, _, _ string,
		) (clusterTLS, error) {
			callCount.Add(1)

			return clusterTLS{host: "h", caData: "Z2tlLWNh"}, nil
		},
	}

	rawArgs := json.RawMessage(
		`{"gke_auth":{"cluster_name":"test-cluster","location":"us-central1","project":"my-project"}}`,
	)

	// First call — should hit the API.
	got1, err1 := p.CACertData(context.Background(), rawArgs)
	if err1 != nil {
		t.Fatalf("first call: unexpected error: %v", err1)
	}

	if got1 != "Z2tlLWNh" {
		t.Errorf("first call: expected cert data, got: %q", got1)
	}

	// Second call — should use cache, not the API.
	got2, err2 := p.CACertData(context.Background(), rawArgs)
	if err2 != nil {
		t.Fatalf("second call: unexpected error: %v", err2)
	}

	if got2 != got1 {
		t.Errorf("second call: expected same result, got: %q", got2)
	}

	if callCount.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", callCount.Load())
	}
}

// --- GCP Provider tests ---

// newTestGCPProviderFromToken builds a gcpProvider with a fixed scoped token
// source and no hardening, for legacy Name/Description/InjectAuth tests.
func newTestGCPProviderFromToken(ts oauth2.TokenSource) *gcpProvider {
	p := &gcpProvider{ //nolint:exhaustruct // test helper; zero values intentional.
		catalog: nil,
	}
	p.doLazyResolve = func(_ context.Context) error {
		p.tokenSource = ts
		return nil
	}
	return p
}

func TestGCPProvider_NameAndDescription(t *testing.T) {
	t.Parallel()

	p := newTestGCPProviderFromToken(mockTokenSource(&oauth2.Token{}, nil))

	if p.Name() != "gcp" {
		t.Errorf("expected name 'gcp', got %q", p.Name())
	}

	if !strings.Contains(p.Description(), "Google Cloud") {
		t.Errorf("expected description to mention Google Cloud, got %q", p.Description())
	}
}

func TestGCPProvider_InjectAuth_Success(t *testing.T) {
	t.Parallel()

	p := newTestGCPProviderFromToken(mockTokenSource(&oauth2.Token{AccessToken: "ya29.test-token"}, nil))

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://compute.googleapis.com/compute/v1/projects/my-project", nil,
	)

	if err := p.InjectAuth(req, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer ya29.test-token" {
		t.Errorf("expected 'Bearer ya29.test-token', got %q", got)
	}
}

func TestGCPProvider_InjectAuth_TokenError(t *testing.T) {
	t.Parallel()

	p := newTestGCPProviderFromToken(mockTokenSource(nil, errors.New("token expired")))

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://storage.googleapis.com/my-bucket", nil,
	)

	err := p.InjectAuth(req, nil)
	if err == nil {
		t.Fatal("expected error from token retrieval failure")
	}

	if !strings.Contains(err.Error(), "failed to retrieve") {
		t.Errorf("expected GCP token error, got: %v", err)
	}
}

// --- GKE Provider tests ---

func TestGKEProvider_NameAndDescription(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{tokenSource: mockTokenSource(&oauth2.Token{}, nil)}

	if p.Name() != "gke" {
		t.Errorf("expected name 'gke', got %q", p.Name())
	}

	if !strings.Contains(p.Description(), "GKE") {
		t.Errorf("expected description to mention GKE, got %q", p.Description())
	}
}

func TestGKEProvider_InjectAuth_Success(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{
		tokenSource: mockTokenSource(&oauth2.Token{AccessToken: "ya29.gke-test"}, nil),
	}

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://gke-cluster.example.com/api/v1/pods", nil,
	)

	if err := p.InjectAuth(req, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer ya29.gke-test" {
		t.Errorf("expected 'Bearer ya29.gke-test', got %q", got)
	}
}

func TestGKEProvider_InjectAuth_TokenError(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{
		tokenSource: mockTokenSource(nil, errors.New("token expired")),
	}

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://gke-cluster.example.com/api/v1/pods", nil,
	)

	err := p.InjectAuth(req, nil)
	if err == nil {
		t.Fatal("expected error from token retrieval failure")
	}

	if !strings.Contains(err.Error(), "failed to retrieve GCP token for GKE") {
		t.Errorf("expected GKE token error, got: %v", err)
	}
}

// --- GKE CACertData programmatic resolution tests ---

func TestGKEProvider_CACertData_Success(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{
		tokenSource: mockTokenSource(&oauth2.Token{}, nil),
		getCluster: func(
			_ context.Context, _ oauth2.TokenSource, project, location, name string,
		) (clusterTLS, error) {
			if project != "my-project" || location != "us-central1" || name != "test-cluster" {
				t.Errorf("unexpected args: project=%q location=%q name=%q", project, location, name)
			}

			return clusterTLS{host: "h", caData: "dGVzdC1jYQ=="}, nil
		},
	}

	rawArgs := json.RawMessage(
		`{"gke_auth":{"cluster_name":"test-cluster","location":"us-central1","project":"my-project"}}`,
	)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "dGVzdC1jYQ==" {
		t.Errorf("expected cert data, got: %q", got)
	}
}

func TestGKEProvider_CACertData_APIError(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{
		tokenSource: mockTokenSource(&oauth2.Token{}, nil),
		getCluster: func(
			_ context.Context, _ oauth2.TokenSource, _, _, _ string,
		) (clusterTLS, error) {
			return clusterTLS{}, errors.New("gke get boom")
		},
	}

	rawArgs := json.RawMessage(
		`{"gke_auth":{"cluster_name":"test-cluster","location":"us-central1","project":"my-project"}}`,
	)

	_, err := p.CACertData(context.Background(), rawArgs)
	if err == nil {
		t.Fatal("expected error from API failure")
	}

	if !strings.Contains(err.Error(), "gke get boom") {
		t.Errorf("expected API error, got: %v", err)
	}
}

func TestGKEProvider_CACertData_NilArgs(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{tokenSource: mockTokenSource(&oauth2.Token{}, nil)}

	got, err := p.CACertData(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "" {
		t.Errorf("expected empty, got: %q", got)
	}
}

func TestGKEProvider_CACertData_BadJSON(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{tokenSource: mockTokenSource(&oauth2.Token{}, nil)}

	_, err := p.CACertData(context.Background(), json.RawMessage(`{bad json}`))
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}
}

func TestGKEProvider_CACertData_MissingFields(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{tokenSource: mockTokenSource(&oauth2.Token{}, nil)}

	// Missing location and project — should return empty without error.
	rawArgs := json.RawMessage(`{"gke_auth":{"cluster_name":"test-cluster"}}`)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "" {
		t.Errorf("expected empty, got: %q", got)
	}
}

// --- defaultEKSDescribeCluster tests ---

func TestDefaultEKSDescribeCluster_Success(t *testing.T) {
	t.Parallel()

	// Mock EKS API server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{
			"cluster": {
				"name": "my-cluster",
				"endpoint": "https://abc.gr7.us-east-1.eks.amazonaws.com",
				"certificateAuthority": {"data": "dGVzdC1jYQ=="}
			}
		}`))
	}))
	t.Cleanup(srv.Close)

	cfg := aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.CredentialsProviderFunc(fakeAWSCreds),
		BaseEndpoint: aws.String(srv.URL),
	}

	ct, err := defaultEKSDescribeCluster(context.Background(), cfg, "my-cluster")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ct.caData != "dGVzdC1jYQ==" {
		t.Errorf("expected caData 'dGVzdC1jYQ==', got %q", ct.caData)
	}

	if ct.host != "abc.gr7.us-east-1.eks.amazonaws.com" {
		t.Errorf("expected host 'abc.gr7.us-east-1.eks.amazonaws.com', got %q", ct.host)
	}
}

func TestDefaultEKSDescribeCluster_NoCert(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"cluster": {"name": "my-cluster"}}`))
	}))
	t.Cleanup(srv.Close)

	cfg := aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.CredentialsProviderFunc(fakeAWSCreds),
		BaseEndpoint: aws.String(srv.URL),
	}

	_, err := defaultEKSDescribeCluster(context.Background(), cfg, "my-cluster")
	if err == nil {
		t.Fatal("expected error for missing CA cert data")
	}

	if !strings.Contains(err.Error(), "has no CA certificate data") {
		t.Errorf("expected 'has no CA certificate data' error, got: %v", err)
	}
}

func TestDefaultEKSDescribeCluster_NoEndpoint(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"cluster": {"name": "my-cluster", "certificateAuthority": {"data": "dGVzdC1jYQ=="}}}`))
	}))
	t.Cleanup(srv.Close)

	cfg := aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.CredentialsProviderFunc(fakeAWSCreds),
		BaseEndpoint: aws.String(srv.URL),
	}

	_, err := defaultEKSDescribeCluster(context.Background(), cfg, "my-cluster")
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}

	if !strings.Contains(err.Error(), "has no endpoint") {
		t.Errorf("expected 'has no endpoint' error, got: %v", err)
	}
}

func TestDefaultEKSDescribeCluster_APIError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"cluster not found"}`))
	}))
	t.Cleanup(srv.Close)

	cfg := aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.CredentialsProviderFunc(fakeAWSCreds),
		BaseEndpoint: aws.String(srv.URL),
	}

	_, err := defaultEKSDescribeCluster(context.Background(), cfg, "nonexistent")
	if err == nil {
		t.Fatal("expected error from API failure")
	}

	if !strings.Contains(err.Error(), "failed to describe EKS cluster") {
		t.Errorf("expected describe error, got: %v", err)
	}
}

// --- defaultGKEGetCluster tests ---

func TestDefaultGKENewContainerService(t *testing.T) {
	t.Parallel()

	ts := mockTokenSource(&oauth2.Token{AccessToken: "ya29.test"}, nil)

	svc, err := defaultGKENewContainerService(context.Background(), ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestDefaultGKEGetCluster_Success(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "my-cluster",
			"endpoint": "34.71.1.2",
			"masterAuth": {"clusterCaCertificate": "dGVzdC1jYQ=="}
		}`))
	}))
	t.Cleanup(srv.Close)

	newSvc := func(ctx context.Context, _ oauth2.TokenSource) (*container.Service, error) {
		return container.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
	}

	ts := mockTokenSource(&oauth2.Token{AccessToken: "ya29.test"}, nil)

	ct, err := defaultGKEGetCluster(context.Background(), newSvc, ts, "my-project", "us-central1", "my-cluster")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ct.caData != "dGVzdC1jYQ==" {
		t.Errorf("expected caData 'dGVzdC1jYQ==', got %q", ct.caData)
	}

	if ct.host != "34.71.1.2" {
		t.Errorf("expected host '34.71.1.2', got %q", ct.host)
	}
}

func TestDefaultGKEGetCluster_NoCert(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name": "my-cluster", "masterAuth": {}}`))
	}))
	t.Cleanup(srv.Close)

	newSvc := func(ctx context.Context, _ oauth2.TokenSource) (*container.Service, error) {
		return container.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
	}

	ts := mockTokenSource(&oauth2.Token{AccessToken: "ya29.test"}, nil)

	_, err := defaultGKEGetCluster(context.Background(), newSvc, ts, "my-project", "us-central1", "my-cluster")
	if err == nil {
		t.Fatal("expected error for missing CA cert data")
	}

	if !strings.Contains(err.Error(), "has no CA certificate data") {
		t.Errorf("expected 'has no CA certificate data' error, got: %v", err)
	}
}

func TestDefaultGKEGetCluster_NoEndpoint(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name": "my-cluster", "masterAuth": {"clusterCaCertificate": "dGVzdC1jYQ=="}}`))
	}))
	t.Cleanup(srv.Close)

	newSvc := func(ctx context.Context, _ oauth2.TokenSource) (*container.Service, error) {
		return container.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
	}

	ts := mockTokenSource(&oauth2.Token{AccessToken: "ya29.test"}, nil)

	_, err := defaultGKEGetCluster(context.Background(), newSvc, ts, "my-project", "us-central1", "my-cluster")
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}

	if !strings.Contains(err.Error(), "has no endpoint") {
		t.Errorf("expected 'has no endpoint' error, got: %v", err)
	}
}

func TestDefaultGKEGetCluster_APIError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": {"message": "not found", "code": 404}}`))
	}))
	t.Cleanup(srv.Close)

	newSvc := func(ctx context.Context, _ oauth2.TokenSource) (*container.Service, error) {
		return container.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
	}

	ts := mockTokenSource(&oauth2.Token{AccessToken: "ya29.test"}, nil)

	_, err := defaultGKEGetCluster(context.Background(), newSvc, ts, "my-project", "us-central1", "nonexistent")
	if err == nil {
		t.Fatal("expected error from API failure")
	}

	if !strings.Contains(err.Error(), "failed to get GKE cluster") {
		t.Errorf("expected get error, got: %v", err)
	}
}

func TestDefaultGKEGetCluster_ServiceCreationError(t *testing.T) {
	t.Parallel()

	newSvc := func(_ context.Context, _ oauth2.TokenSource) (*container.Service, error) {
		return nil, errors.New("service creation boom")
	}

	ts := mockTokenSource(&oauth2.Token{AccessToken: "ya29.test"}, nil)

	_, err := defaultGKEGetCluster(context.Background(), newSvc, ts, "my-project", "us-central1", "my-cluster")
	if err == nil {
		t.Fatal("expected error from service creation failure")
	}

	if !strings.Contains(err.Error(), "failed to create GKE container service") {
		t.Errorf("expected service creation error, got: %v", err)
	}
}

// --- AKS Provider tests ---

func TestAKSProvider_NameAndDescription(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	if p.Name() != "aks" {
		t.Errorf("expected name 'aks', got %q", p.Name())
	}

	if !strings.Contains(p.Description(), "AKS") {
		t.Errorf("expected description to mention AKS, got %q", p.Description())
	}
}

func TestAKSProvider_InjectAuth_AADFallback(t *testing.T) {
	t.Parallel()

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{Token: "eyJ0eXAiOi.fake-aks-token"}, nil),
	}

	rawArgs, _ := json.Marshal(map[string]any{
		"aks_auth": map[string]string{"cluster_name": "my-cluster"},
	})

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://my-cluster-dns.hcp.eastus.azmk8s.io/api/v1/pods", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer eyJ0eXAiOi.fake-aks-token" {
		t.Errorf("expected 'Bearer eyJ0eXAiOi.fake-aks-token', got %q", got)
	}
}

func TestAKSProvider_InjectAuth_AADFallback_Error(t *testing.T) {
	t.Parallel()

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, errors.New("token expired")),
	}

	rawArgs, _ := json.Marshal(map[string]any{
		"aks_auth": map[string]string{"cluster_name": "my-cluster"},
	})

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://my-cluster-dns.hcp.eastus.azmk8s.io/api/v1/pods", nil,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error from token retrieval failure")
	}

	if !strings.Contains(err.Error(), "failed to retrieve Azure token for AKS AAD fallback") {
		t.Errorf("expected AKS token error, got: %v", err)
	}
}

func TestAKSProvider_InjectAuth_MissingCluster(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	rawArgs, _ := json.Marshal(map[string]any{
		"aks_auth": map[string]string{},
	})

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://example.com", nil,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error when aks_auth.cluster_name is missing")
	}

	if !strings.Contains(err.Error(), "aks_auth.cluster_name is required") {
		t.Errorf("expected 'aks_auth.cluster_name is required' in error, got: %v", err)
	}
}

func TestAKSProvider_InjectAuth_InvalidJSON(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://example.com", nil,
	)

	err := p.InjectAuth(req, json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error from invalid JSON")
	}

	if !strings.Contains(err.Error(), "failed to parse aks_auth args") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestAKSProvider_InjectAuth_NilAKSAuthField(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://example.com", nil,
	)

	// Valid JSON but no "aks_auth" key → parsed.AKSAuth is nil → clusterName is "".
	rawArgs, _ := json.Marshal(map[string]any{})

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error when aks_auth field is absent")
	}

	if !strings.Contains(err.Error(), "aks_auth.cluster_name is required") {
		t.Errorf("expected 'aks_auth.cluster_name is required' in error, got: %v", err)
	}
}

// --- AKS integration tests ---
// These tests inject an aksNewClientFunc that builds an ARM client pointing at
// an httptest.Server returning mock ARM API responses. This exercises the full
// aksGetClusterConfig code path (client creation → API call → kubeconfig
// parsing → behavior).

// aksARMMock returns an [httptest.Server] that emulates the ARM
// ListClusterAdminCredentials endpoint.
func aksARMMock(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	return srv
}

// aksClientFor returns an aksNewClientFunc that creates an ARM client pointing
// at the given base URL via the supplied HTTP client. Injected as the provider's
// newClient seam (or passed directly to aksGetClusterConfig).
func aksClientFor(baseURL string, httpClient *http.Client) aksNewClientFunc {
	return func(
		subscriptionID string, cred azcore.TokenCredential, _ cloud.Configuration,
	) (*armcontainerservice.ManagedClustersClient, error) {
		return armcontainerservice.NewManagedClustersClient(
			subscriptionID, cred,
			&arm.ClientOptions{ClientOptions: policy.ClientOptions{
				Transport: httpClient,
				Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
					cloud.ResourceManager: {Endpoint: baseURL, Audience: baseURL},
				}},
			}},
		)
	}
}

// fakeKubeconfigToken returns a minimal kubeconfig YAML with a Bearer token.
func fakeKubeconfigToken() string {
	return `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://my-cluster-dns.hcp.eastus.azmk8s.io:443
  name: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: clusterAdmin_my-rg_my-cluster
  name: my-cluster
current-context: my-cluster
users:
- name: clusterAdmin_my-rg_my-cluster
  user:
    token: fake-local-token`
}

// fakeKubeconfigMTLS returns a minimal kubeconfig YAML with mTLS client certs.
func fakeKubeconfigMTLS(certBase64, keyBase64 string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://my-cluster-dns.hcp.eastus.azmk8s.io:443
  name: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: clusterAdmin_my-rg_my-cluster
  name: my-cluster
current-context: my-cluster
users:
- name: clusterAdmin_my-rg_my-cluster
  user:
    client-certificate-data: %s
    client-key-data: %s`, certBase64, keyBase64)
}

// fakeKubeconfigAAD returns a minimal kubeconfig YAML with an exec plugin (AAD).
func fakeKubeconfigAAD(caBase64 string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: %s
    server: https://my-cluster-dns.hcp.eastus.azmk8s.io:443
  name: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: clusterUser_my-rg_my-cluster
  name: my-cluster
current-context: my-cluster
users:
- name: clusterUser_my-rg_my-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args:
      - get-token`, caBase64)
}

func TestAKSProvider_InjectAuth_LocalToken(t *testing.T) {
	t.Parallel()

	kubeconfig := fakeKubeconfigToken()
	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(kubeconfig))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://my-cluster-dns.hcp.eastus.azmk8s.io/api/v1/pods", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer fake-local-token" {
		t.Errorf("expected 'Bearer fake-local-token', got %q", got)
	}
}

func TestAKSProvider_InjectAuth_LocalmTLS(t *testing.T) {
	t.Parallel()

	certData := base64.StdEncoding.EncodeToString([]byte("test-client-cert"))
	keyData := base64.StdEncoding.EncodeToString([]byte("test-client-key"))
	kubeconfig := fakeKubeconfigMTLS(certData, keyData)
	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(kubeconfig))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://my-cluster-dns.hcp.eastus.azmk8s.io/api/v1/pods", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// mTLS doesn't set Authorization header!
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("expected no Authorization header for mTLS, got %q", got)
	}
}

func TestAKSProvider_InjectAuth_ConfigError(t *testing.T) {
	t.Parallel()

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://my-cluster-dns.hcp.eastus.azmk8s.io/api/v1/pods", nil,
	)

	err := p.InjectAuth(req, rawArgs)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "500 Internal Server Error") {
		t.Errorf("expected error to contain '500 Internal Server Error', got %v", err)
	}
}

func TestAKSProvider_InjectAuth_ExecPluginFallback(t *testing.T) {
	t.Parallel()

	caData := base64.StdEncoding.EncodeToString([]byte("test-ca-cert"))
	kubeconfig := fakeKubeconfigAAD(caData)
	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(kubeconfig))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterUser","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{Token: "eyJ0eXAiOi.fake-aad-token"}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"https://my-cluster-dns.hcp.eastus.azmk8s.io/api/v1/pods", nil,
	)

	if err := p.InjectAuth(req, rawArgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer eyJ0eXAiOi.fake-aad-token" {
		t.Errorf("expected 'Bearer eyJ0eXAiOi.fake-aad-token', got %q", got)
	}
}

func TestAKSProvider_CACertData_Success(t *testing.T) {
	t.Parallel()

	caData := base64.StdEncoding.EncodeToString([]byte("test-ca-cert"))
	kubeconfig := fakeKubeconfigAAD(caData)
	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(kubeconfig))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != caData {
		t.Errorf("expected %q, got %q", caData, got)
	}
}

func TestAKSProvider_CACertData_APIError(t *testing.T) {
	t.Parallel()

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"ResourceNotFound","message":"cluster not found"}}`))
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"missing","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	_, err := p.CACertData(context.Background(), rawArgs)
	if err == nil {
		t.Fatal("expected error from API failure")
	}

	if !strings.Contains(err.Error(), "failed to list AKS cluster") {
		t.Errorf("expected list error, got: %v", err)
	}
}

func TestAKSProvider_CACertData_NilArgs(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	got, err := p.CACertData(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "" {
		t.Errorf("expected empty, got: %q", got)
	}
}

func TestAKSProvider_CACertData_BadJSON(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	_, err := p.CACertData(context.Background(), json.RawMessage(`{bad json}`))
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}
}

func TestAKSProvider_CACertData_MissingFields(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	// Missing resource_group and subscription_id — should return empty without error.
	// The provider gracefully skips ARM lookup when these aren't provided.
	rawArgs := json.RawMessage(`{"aks_auth":{"cluster_name":"my-cluster"}}`)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "" {
		t.Errorf("expected empty, got: %q", got)
	}
}

func TestAKSProvider_CACertData_NoCAData(t *testing.T) {
	t.Parallel()

	// Reusing the AAD fallback kubeconfig format since it has no CAData inside.
	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(fakeKubeconfigAAD("")))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterUser","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "" {
		t.Errorf("expected empty string since no CA was in config, got %q", got)
	}
}

func TestAKSProvider_CACertData_EmptyClusterName(t *testing.T) {
	t.Parallel()

	// FIX: the tolerance guard now requires all three fields (cluster_name,
	// resource_group, subscription_id) to match getClusterConfig. A payload
	// missing cluster_name is tolerated and returns empty without error,
	// matching the eks/gke siblings — and crucially never reaches the ARM
	// client (none is wired here).
	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	rawArgs := json.RawMessage(`{"aks_auth":{"resource_group":"my-rg","subscription_id":"sub-123"}}`)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty, got: %q", got)
	}
}

func TestAKSProvider_ClientCertData_EmptyClusterName(t *testing.T) {
	t.Parallel()

	// FIX twin: ClientCertData's tolerance guard also requires all three, so a
	// missing cluster_name returns empty/empty/nil without touching the ARM API.
	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	rawArgs := json.RawMessage(`{"aks_auth":{"resource_group":"my-rg","subscription_id":"sub-123"}}`)

	gotCert, gotKey, err := p.ClientCertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCert != "" || gotKey != "" {
		t.Errorf("expected empty cert/key, got %q, %q", gotCert, gotKey)
	}
}

func TestAKSProvider_ClientCertData_Success(t *testing.T) {
	t.Parallel()

	certData := base64.StdEncoding.EncodeToString([]byte("test-client-cert"))
	keyData := base64.StdEncoding.EncodeToString([]byte("test-client-key"))
	kubeconfig := fakeKubeconfigMTLS(certData, keyData)
	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(kubeconfig))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	gotCert, gotKey, err := p.ClientCertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCert != certData || gotKey != keyData {
		t.Errorf("expected cert %q and key %q, got %q and %q", certData, keyData, gotCert, gotKey)
	}
}

func TestAKSProvider_ClientCertData_NoCerts(t *testing.T) {
	t.Parallel()

	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(fakeKubeconfigAAD("")))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterUser","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	gotCert, gotKey, err := p.ClientCertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCert != "" || gotKey != "" {
		t.Errorf("expected empty cert/key since no client certs in config, got %q, %q", gotCert, gotKey)
	}
}

func TestAKSProvider_ClientCertData_NilArgs(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	gotCert, gotKey, err := p.ClientCertData(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCert != "" || gotKey != "" {
		t.Errorf("expected empty, got: %q, %q", gotCert, gotKey)
	}
}

func TestAKSProvider_ClientCertData_BadJSON(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	_, _, err := p.ClientCertData(context.Background(), json.RawMessage(`{bad}`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse aks_auth args") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAKSProvider_ClientCertData_MissingFields(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	rawArgs := json.RawMessage(`{"aks_auth":{"cluster_name":"my-cluster"}}`)

	gotCert, gotKey, err := p.ClientCertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCert != "" || gotKey != "" {
		t.Errorf("expected empty, got: %q, %q", gotCert, gotKey)
	}
}

func TestAKSProvider_ClientCertData_APIError(t *testing.T) {
	t.Parallel()

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"ResourceNotFound"}}`))
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	_, _, err := p.ClientCertData(context.Background(), rawArgs)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "ResourceNotFound") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAKSProvider_CacheHit(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int64

	caData := base64.StdEncoding.EncodeToString([]byte("test-ca-cert"))
	kubeconfig := fakeKubeconfigAAD(caData)
	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(kubeconfig))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	rawArgs := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	// First call to CA
	_, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}

	// Second call to ClientCertData
	_, _, err = p.ClientCertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}

	if callCount.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", callCount.Load())
	}
}

// --- aksGetClusterConfig direct tests ---

func TestAKSGetClusterConfig_NoKubeconfigs(t *testing.T) {
	t.Parallel()

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kubeconfigs":[]}`))
	})

	_, err := aksGetClusterConfig(
		context.Background(),
		aksClientFor(srv.URL, srv.Client()),
		mockCredential(azcore.AccessToken{}, nil),
		cloud.Configuration{},
		"sub-123",
		"my-rg",
		"my-cluster",
	)
	if err == nil {
		t.Fatal("expected error for empty kubeconfigs")
	}

	if !strings.Contains(err.Error(), "returned no kubeconfig credentials") {
		t.Errorf("expected 'returned no kubeconfig credentials' error, got: %v", err)
	}
}

func TestAKSGetClusterConfig_InvalidKubeconfig(t *testing.T) {
	t.Parallel()

	invalidB64 := base64.StdEncoding.EncodeToString([]byte("not-valid-yaml: [[["))

	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, invalidB64)
	})

	_, err := aksGetClusterConfig(
		context.Background(),
		aksClientFor(srv.URL, srv.Client()),
		mockCredential(azcore.AccessToken{}, nil),
		cloud.Configuration{},
		"sub-123",
		"my-rg",
		"my-cluster",
	)
	if err == nil {
		t.Fatal("expected error for invalid kubeconfig")
	}

	if !strings.Contains(err.Error(), "failed to parse AKS kubeconfig") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestAKSGetClusterConfig_ClientCreateError(t *testing.T) {
	t.Parallel()

	newClient := func(
		_ string, _ azcore.TokenCredential, _ cloud.Configuration,
	) (*armcontainerservice.ManagedClustersClient, error) {
		return nil, errors.New("client create boom")
	}

	_, err := aksGetClusterConfig(
		context.Background(),
		newClient,
		mockCredential(azcore.AccessToken{}, nil),
		cloud.Configuration{},
		"sub-123",
		"my-rg",
		"my-cluster",
	)
	if err == nil {
		t.Fatal("expected error from client creation failure")
	}

	if !strings.Contains(err.Error(), "failed to create AKS client") {
		t.Errorf("expected client create error, got: %v", err)
	}
}

func TestAKSProvider_getClusterConfig_InvalidArgs(t *testing.T) {
	t.Parallel()

	// getClusterConfig keeps its own validate guard as defense-in-depth for any
	// direct caller, independent of the up-front guards in the public methods.
	// A nil-client provider proves it fails closed before touching the ARM API.
	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	_, err := p.getClusterConfig(context.Background(), &AKSAuthArgs{ClusterName: "c", ResourceGroup: "rg"})
	if err == nil {
		t.Fatal("expected validation error for missing subscription_id")
	}

	if !strings.Contains(err.Error(), "cluster_name, resource_group, and subscription_id are required") {
		t.Errorf("expected the required-fields message, got %v", err)
	}
}

func TestDefaultAKSNewManagedClustersClient(t *testing.T) {
	t.Parallel()

	client, err := defaultAKSNewManagedClustersClient(
		"sub-123",
		mockCredential(azcore.AccessToken{}, nil),
		cloud.Configuration{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestAWSProvider_AuthorizesHost_strictDispatch(t *testing.T) {
	t.Parallel()

	// AuthorizesHost does not call ensureReady — nil closure is intentional.
	p := newAWSProvider(aws.Config{}, nil)

	cases := []struct {
		name   string
		host   string
		args   string
		wantOK bool
	}{
		{"happy", "s3.us-east-1.amazonaws.com", `{"aws_auth":{"service":"s3","region":"us-east-1"}}`, true},
		{
			"service mismatch",
			"s3.us-east-1.amazonaws.com",
			`{"aws_auth":{"service":"iam","region":"us-east-1"}}`,
			false,
		},
		{"region mismatch", "s3.us-east-1.amazonaws.com", `{"aws_auth":{"service":"s3","region":"eu-west-1"}}`, false},
		{
			"vpc endpoint",
			"vpce-0a1b.s3.us-east-1.amazonaws.com",
			`{"aws_auth":{"service":"s3","region":"us-east-1"}}`,
			false,
		},
		{"non-aws host", "attacker.com", `{"aws_auth":{"service":"s3","region":"us-east-1"}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ok, _ := p.AuthorizesHost(t.Context(), c.host, json.RawMessage(c.args))
			if ok != c.wantOK {
				t.Errorf("AuthorizesHost(%q, %s) = %v, want %v", c.host, c.args, ok, c.wantOK)
			}
		})
	}
}

func TestAWSProvider_AuthorizesHost_missingAWSAuth(t *testing.T) {
	t.Parallel()
	// AuthorizesHost does not call ensureReady — nil closure is intentional.
	p := newAWSProvider(aws.Config{}, nil)
	_, err := p.AuthorizesHost(t.Context(), "s3.us-east-1.amazonaws.com", json.RawMessage(`{}`))
	if err == nil {
		t.Errorf("expected error for missing aws_auth, got nil")
	}
}

func TestAWSProvider_AuthorizesHost_malformedArgs(t *testing.T) {
	t.Parallel()
	// AuthorizesHost does not call ensureReady — nil closure is intentional.
	p := newAWSProvider(aws.Config{}, nil)
	_, err := p.AuthorizesHost(t.Context(), "s3.us-east-1.amazonaws.com", json.RawMessage(`{bad`))
	if err == nil {
		t.Errorf("expected error for malformed JSON, got nil")
	}
}

// fakeAWSModels is a stub awshardening.ModelResolver for exercising the parent
// provider's signing-name resolution against a real *awshardening.Provider.
type fakeAWSModels struct {
	models []*awshardening.ServiceModel
	err    error
}

func (f fakeAWSModels) Resolve(context.Context, string) ([]*awshardening.ServiceModel, error) {
	return f.models, f.err
}

// fakeAWSActionResolver / fakeAWSEvaluator satisfy NewProvider's remaining ports;
// ResolveSigningName never invokes them.
type fakeAWSActionResolver struct{}

func (fakeAWSActionResolver) Resolve(
	context.Context, *awshardening.ServiceModel, string,
) ([]string, awshardening.ActionSource) {
	return nil, awshardening.SourceNone
}

type fakeAWSEvaluator struct{}

func (fakeAWSEvaluator) AllowedAll(context.Context, []string) (bool, error) { return true, nil }

func newAWSProviderWithModels(t *testing.T, models []*awshardening.ServiceModel, err error) *awsProvider {
	t.Helper()
	p := newAWSProvider(aws.Config{Region: "us-east-1"}, func(context.Context) error { return nil })
	p.actionProvider = awshardening.NewProvider(
		fakeAWSModels{models: models, err: err}, fakeAWSActionResolver{}, fakeAWSEvaluator{}, "arn",
	)
	return p
}

// TestAWSProvider_AuthorizesHost_signingNameAlias verifies the host check
// accepts a claim that is the SigV4 signing name ("ecr") even though the host's
// endpoint prefix differs ("api.ecr") — the ECR case.
func TestAWSProvider_AuthorizesHost_signingNameAlias(t *testing.T) {
	t.Parallel()
	p := newAWSProviderWithModels(t,
		[]*awshardening.ServiceModel{{EndpointPrefix: "api.ecr", SigningName: "ecr"}}, nil)
	ok, err := p.AuthorizesHost(t.Context(), "api.ecr.us-east-1.amazonaws.com",
		json.RawMessage(`{"aws_auth":{"service":"ecr","region":"us-east-1"}}`))
	if err != nil || !ok {
		t.Errorf("AuthorizesHost(ecr alias) = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestAWSProvider_AuthorizesHost_signingNameMismatch rejects a claim that
// matches neither the endpoint prefix nor the resolved signing name.
func TestAWSProvider_AuthorizesHost_signingNameMismatch(t *testing.T) {
	t.Parallel()
	p := newAWSProviderWithModels(t,
		[]*awshardening.ServiceModel{{EndpointPrefix: "api.ecr", SigningName: "ecr"}}, nil)
	ok, _ := p.AuthorizesHost(t.Context(), "api.ecr.us-east-1.amazonaws.com",
		json.RawMessage(`{"aws_auth":{"service":"ecr-typo","region":"us-east-1"}}`))
	if ok {
		t.Error("AuthorizesHost(ecr-typo) = true, want false")
	}
}

// TestAWSProvider_AuthorizesHost_signingNameResolveError rejects when the model
// archive cannot resolve a signing name (surfaces the original mismatch).
func TestAWSProvider_AuthorizesHost_signingNameResolveError(t *testing.T) {
	t.Parallel()
	p := newAWSProviderWithModels(t, nil, errors.New("archive unavailable"))
	ok, err := p.AuthorizesHost(t.Context(), "api.ecr.us-east-1.amazonaws.com",
		json.RawMessage(`{"aws_auth":{"service":"ecr","region":"us-east-1"}}`))
	if ok || err == nil {
		t.Errorf("AuthorizesHost(resolve error) = (%v, %v), want (false, err)", ok, err)
	}
}

// TestAWSProvider_AuthorizesHost_signingNameActionProviderNil rejects when the
// claim differs from the prefix but the action provider was never initialized.
func TestAWSProvider_AuthorizesHost_signingNameActionProviderNil(t *testing.T) {
	t.Parallel()
	// no-op doLazyResolve succeeds but never sets actionProvider.
	p := newAWSProvider(aws.Config{Region: "us-east-1"}, func(context.Context) error { return nil })
	ok, _ := p.AuthorizesHost(t.Context(), "api.ecr.us-east-1.amazonaws.com",
		json.RawMessage(`{"aws_auth":{"service":"ecr","region":"us-east-1"}}`))
	if ok {
		t.Error("AuthorizesHost(nil action provider) = true, want false")
	}
}

// TestAWSProvider_AuthorizesHost_s3ControlClaims pins the end-to-end host gate
// for all three aws_auth.service claim spellings that resolve to S3 Control.
func TestAWSProvider_AuthorizesHost_s3ControlClaims(t *testing.T) {
	t.Parallel()
	const host = "123456789012.s3-control.us-east-1.amazonaws.com"

	// Endpoint-prefix and SDK-id spellings reconcile via the relaxed Verify on the
	// strict-dispatch path (no model resolution needed).
	strict := newAWSProvider(aws.Config{}, nil)
	for _, claim := range []string{"s3-control", "s3control"} {
		args := json.RawMessage(`{"aws_auth":{"service":"` + claim + `","region":"us-east-1"}}`)
		ok, err := strict.AuthorizesHost(t.Context(), host, args)
		if !ok || err != nil {
			t.Errorf("AuthorizesHost(claim=%q) = (%v,%v), want (true,nil)", claim, ok, err)
		}
	}
	// Wrong service still denied.
	bad := json.RawMessage(`{"aws_auth":{"service":"iam","region":"us-east-1"}}`)
	if ok, _ := strict.AuthorizesHost(t.Context(), host, bad); ok {
		t.Error("AuthorizesHost(claim=iam) = true, want false")
	}

	// The signing-name spelling "s3" reconciles via the alias path, which resolves
	// the host's signing name from the model archive.
	withModels := newAWSProviderWithModels(t,
		[]*awshardening.ServiceModel{{EndpointPrefix: "s3-control", SigningName: "s3"}}, nil)
	s3 := json.RawMessage(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if ok, err := withModels.AuthorizesHost(t.Context(), host, s3); !ok || err != nil {
		t.Errorf("AuthorizesHost(claim=s3) = (%v,%v), want (true,nil)", ok, err)
	}
}

func TestGCPProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()

	// AuthorizesHost now requires gcp_auth.service and a real catalog. The
	// pre-lazy catalog seam is exercised by the gcp_internal_test.go suite;
	// here we just confirm that missing gcp_auth args → error (fail-closed)
	// and that a rejected host (evil.com) → ParseHost error.
	p := newTestGCPProviderFromToken(mockTokenSource(&oauth2.Token{}, nil))

	_, err := p.AuthorizesHost(context.Background(), "evil.com",
		json.RawMessage(`{"gcp_auth":{"service":"compute"}}`))
	if err == nil {
		t.Fatal("evil.com: expected error from ParseHost, got nil")
	}

	_, err = p.AuthorizesHost(context.Background(), "compute.googleapis.com", nil)
	if err == nil {
		t.Fatal("nil args: expected parse error, got nil")
	}
}

// --- constructor tests (the shell GetProviders is the only production caller) ---

func TestNewGithubProvider(t *testing.T) {
	t.Parallel()

	if got := newGithubProvider("ghp_x", githubhardening.BaselineExposure(), nil).Name(); got != githubProviderName {
		t.Errorf("expected %q, got %q", githubProviderName, got)
	}
}

func TestNewGCPProvider(t *testing.T) {
	t.Parallel()

	if got := newTestGCPProviderFromToken(mockTokenSource(&oauth2.Token{}, nil)).Name(); got != gcpProviderName {
		t.Errorf("expected %q, got %q", gcpProviderName, got)
	}
}

func TestNewAKSProvider(t *testing.T) {
	t.Parallel()

	p := newAKSProvider(mockCredential(azcore.AccessToken{}, nil), cloud.Configuration{})
	if p.Name() != aksProviderName {
		t.Errorf("expected %q, got %q", aksProviderName, p.Name())
	}

	if p.newClient == nil {
		t.Error("expected newClient seam to be wired by the constructor")
	}
}

// --- hostFromEndpoint + EKS AuthorizesHost tests ---

func TestHostFromEndpoint(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"https://ABC123.gr7.us-west-2.eks.amazonaws.com", "abc123.gr7.us-west-2.eks.amazonaws.com"},
		{"34.71.1.2", "34.71.1.2"},
		{"https://my.host:443", "my.host"},
		{"\x7f", ""}, // url.Parse rejects control chars → "".
	}
	for _, c := range cases {
		if got := hostFromEndpoint(c.in); got != c.want {
			t.Errorf("hostFromEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEKSProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()

	newProvider := func() *eksProvider {
		return &eksProvider{
			cfg: aws.Config{Region: "us-east-1"},
			describeCluster: func(_ context.Context, _ aws.Config, _ string) (clusterTLS, error) {
				return clusterTLS{host: "abc123.gr7.us-east-1.eks.amazonaws.com", caData: "Y2E="}, nil
			},
		}
	}

	args := json.RawMessage(`{"eks_auth":{"cluster_name":"c"}}`)

	ok, err := newProvider().AuthorizesHost(context.Background(), "abc123.gr7.us-east-1.eks.amazonaws.com", args)
	if err != nil || !ok {
		t.Fatalf("matching endpoint: ok=%v err=%v, want true/nil", ok, err)
	}

	ok, err = newProvider().AuthorizesHost(context.Background(), "evil.com", args)
	if err != nil || ok {
		t.Fatalf("mismatched host: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestEKSProvider_AuthorizesHost_BadJSON(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}

	_, err := p.AuthorizesHost(context.Background(), "x", json.RawMessage(`{bad json}`))
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}
}

func TestEKSProvider_AuthorizesHost_MissingCluster(t *testing.T) {
	t.Parallel()

	p := &eksProvider{}

	_, err := p.AuthorizesHost(context.Background(), "x", json.RawMessage(`{"eks_auth":{"cluster_name":""}}`))
	if err == nil {
		t.Fatal("expected error when cluster_name is empty")
	}
}

func TestEKSProvider_AuthorizesHost_ResolveError(t *testing.T) {
	t.Parallel()

	p := &eksProvider{
		cfg: aws.Config{Region: "us-east-1"},
		describeCluster: func(_ context.Context, _ aws.Config, _ string) (clusterTLS, error) {
			return clusterTLS{}, errors.New("describe boom")
		},
	}

	_, err := p.AuthorizesHost(context.Background(), "x", json.RawMessage(`{"eks_auth":{"cluster_name":"c"}}`))
	if err == nil || !strings.Contains(err.Error(), "describe boom") {
		t.Fatalf("expected resolve error, got %v", err)
	}
}

// TestNewGKEProvider verifies the constructor wires the GKE seams, including the
// getCluster closure that delegates to defaultGKEGetCluster via the (overridable)
// newContainerService factory.
func TestNewGKEProvider(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"c","endpoint":"34.71.1.2","masterAuth":{"clusterCaCertificate":"Z2tlLWNh"}}`))
	}))
	t.Cleanup(srv.Close)

	p := newGKEProvider(mockTokenSource(&oauth2.Token{}, nil))
	if p.Name() != gkeProviderName {
		t.Errorf("expected %q, got %q", gkeProviderName, p.Name())
	}

	// Redirect the wired factory at the test server so the default getCluster
	// closure runs end-to-end without touching the real GKE API.
	p.newContainerService = func(ctx context.Context, _ oauth2.TokenSource) (*container.Service, error) {
		return container.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
	}

	rawArgs := json.RawMessage(
		`{"gke_auth":{"cluster_name":"test-cluster","location":"us-central1","project":"my-project"}}`,
	)

	got, err := p.CACertData(context.Background(), rawArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "Z2tlLWNh" {
		t.Errorf("expected 'Z2tlLWNh', got %q", got)
	}
}

func TestGKEProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()

	newProvider := func() *gkeProvider {
		return &gkeProvider{
			tokenSource: mockTokenSource(&oauth2.Token{}, nil),
			getCluster: func(_ context.Context, _ oauth2.TokenSource, _, _, _ string) (clusterTLS, error) {
				return clusterTLS{host: "34.71.1.2", caData: "Z2tlLWNh"}, nil
			},
		}
	}

	args := json.RawMessage(`{"gke_auth":{"cluster_name":"c","location":"us-central1","project":"p"}}`)

	ok, err := newProvider().AuthorizesHost(context.Background(), "34.71.1.2", args)
	if err != nil || !ok {
		t.Fatalf("matching IP endpoint: ok=%v err=%v, want true/nil", ok, err)
	}

	ok, err = newProvider().AuthorizesHost(context.Background(), "34.99.99.99", args)
	if err != nil || ok {
		t.Fatalf("mismatched IP: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestGKEProvider_AuthorizesHost_MissingFields(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{}

	_, err := p.AuthorizesHost(context.Background(), "x", json.RawMessage(`{"gke_auth":{"cluster_name":"c"}}`))
	if err == nil {
		t.Fatal("expected error when location/project are empty")
	}
}

func TestGKEProvider_AuthorizesHost_ResolveError(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{
		tokenSource: mockTokenSource(&oauth2.Token{}, nil),
		getCluster: func(_ context.Context, _ oauth2.TokenSource, _, _, _ string) (clusterTLS, error) {
			return clusterTLS{}, errors.New("get boom")
		},
	}

	args := json.RawMessage(`{"gke_auth":{"cluster_name":"c","location":"l","project":"p"}}`)

	_, err := p.AuthorizesHost(context.Background(), "x", args)
	if err == nil || !strings.Contains(err.Error(), "get boom") {
		t.Fatalf("expected resolve error, got %v", err)
	}
}

func TestGKEProvider_AuthorizesHost_BadJSON(t *testing.T) {
	t.Parallel()

	p := &gkeProvider{}

	_, err := p.AuthorizesHost(context.Background(), "x", json.RawMessage(`{bad}`))
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}
}

func TestAKSProvider_AuthorizesHost(t *testing.T) {
	t.Parallel()

	kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(fakeKubeconfigToken()))
	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, kubeconfigB64)
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	args := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	ok, err := p.AuthorizesHost(context.Background(), "my-cluster-dns.hcp.eastus.azmk8s.io", args)
	if err != nil || !ok {
		t.Fatalf("matching endpoint: ok=%v err=%v, want true/nil", ok, err)
	}

	ok, err = p.AuthorizesHost(context.Background(), "evil.com", args)
	if err != nil || ok {
		t.Fatalf("mismatched host: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestAKSProvider_AuthorizesHost_MissingFields(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	_, err := p.AuthorizesHost(
		context.Background(), "x",
		json.RawMessage(`{"aks_auth":{"cluster_name":"my-cluster"}}`),
	)
	if err == nil {
		t.Fatal("expected error when resource_group/subscription_id are missing")
	}
}

func TestAKSProvider_AuthorizesHost_BadJSON(t *testing.T) {
	t.Parallel()

	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	_, err := p.AuthorizesHost(context.Background(), "x", json.RawMessage(`{bad}`))
	if err == nil {
		t.Fatal("expected error from bad JSON")
	}
}

func TestAKSProvider_AuthorizesHost_MissingFields_NoClientCall(t *testing.T) {
	t.Parallel()

	// No newClient wired: if AuthorizesHost validated up-front it returns an
	// error without ever touching the ARM client. If it does not, it would
	// dereference a nil client inside getClusterConfig.
	p := &aksProvider{credential: mockCredential(azcore.AccessToken{}, nil)}

	_, err := p.AuthorizesHost(
		context.Background(), "x",
		json.RawMessage(`{"aks_auth":{"cluster_name":"c","resource_group":"rg"}}`),
	)
	if err == nil {
		t.Fatal("expected up-front validation error for missing subscription_id")
	}
	if !strings.Contains(err.Error(), "cluster_name, resource_group, and subscription_id are required") {
		t.Errorf("expected the up-front required-fields message, got %v", err)
	}
}

func TestAKSProvider_AuthorizesHost_ConfigError(t *testing.T) {
	t.Parallel()

	// All fields present (validate passes), but the ARM API fails — AuthorizesHost
	// must surface the getClusterConfig error.
	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"ResourceNotFound","message":"cluster not found"}}`))
	})

	p := &aksProvider{
		credential: mockCredential(azcore.AccessToken{}, nil),
		newClient:  aksClientFor(srv.URL, srv.Client()),
	}

	args := json.RawMessage(
		`{"aks_auth":{"cluster_name":"missing","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	_, err := p.AuthorizesHost(context.Background(), "x", args)
	if err == nil {
		t.Fatal("expected error from ARM API failure")
	}

	if !strings.Contains(err.Error(), "failed to list AKS cluster") {
		t.Errorf("expected list error, got: %v", err)
	}
}

func TestAKSAuthArgs_validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		args    *AKSAuthArgs
		wantErr bool
	}{
		{"nil", nil, true},
		{"only cluster", &AKSAuthArgs{ClusterName: "c"}, true},
		{"missing sub", &AKSAuthArgs{ClusterName: "c", ResourceGroup: "rg"}, true},
		{"ok", &AKSAuthArgs{ClusterName: "c", ResourceGroup: "rg", SubscriptionID: "s"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if (c.args.validate() != nil) != c.wantErr {
				t.Fatalf("validate()=%v wantErr=%v", c.args.validate(), c.wantErr)
			}
		})
	}
}

// --- AuthorizeHost helper ---

type hostAuthFake struct {
	name string
	ok   bool
	err  error
}

func (f *hostAuthFake) Name() string                                        { return f.name }
func (f *hostAuthFake) Description() string                                 { return "fake" }
func (f *hostAuthFake) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }
func (f *hostAuthFake) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return f.ok, f.err
}

func TestAuthorizeHost(t *testing.T) {
	t.Parallel()

	providers := []Provider{&hostAuthFake{name: "p", ok: true}}

	if err := AuthorizeHost(context.Background(), "p", "any.host", providers, nil); err != nil {
		t.Fatalf("allowed host: unexpected error: %v", err)
	}
}

func TestAuthorizeHost_Denied(t *testing.T) {
	t.Parallel()

	providers := []Provider{&hostAuthFake{name: "p", ok: false}}

	err := AuthorizeHost(context.Background(), "p", "evil.com", providers, nil)
	if !errors.Is(err, ErrHostNotAuthorized) {
		t.Fatalf("expected ErrHostNotAuthorized, got %v", err)
	}
}

func TestAuthorizeHost_ResolveError(t *testing.T) {
	t.Parallel()

	providers := []Provider{&hostAuthFake{name: "p", err: errors.New("resolve boom")}}

	err := AuthorizeHost(context.Background(), "p", "x", providers, nil)
	if err == nil || !strings.Contains(err.Error(), "resolve boom") {
		t.Fatalf("expected resolve error, got %v", err)
	}
}

func TestAuthorizeHost_UnknownProvider(t *testing.T) {
	t.Parallel()

	err := AuthorizeHost(context.Background(), "nope", "x", nil, nil)
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("expected ErrUnknownProvider, got %v", err)
	}
}

func TestAuthorizeHost_CaseInsensitive(t *testing.T) {
	t.Parallel()

	providers := []Provider{&hostAuthFake{name: "github", ok: true}}

	if err := AuthorizeHost(context.Background(), "GitHub", "api.github.com", providers, nil); err != nil {
		t.Fatalf("case-insensitive match: unexpected error: %v", err)
	}
}

// --- AuthorizeAction dispatcher tests ---

func TestAuthorizeAction_callsProviderImplementingActionAuthorizer(t *testing.T) {
	t.Parallel()

	called := false
	provider := &fakeAuthorizingProvider{
		name: "aws",
		authorizeAction: func(_ context.Context, _ *http.Request, _ json.RawMessage) error {
			called = true
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example/", nil)

	err := AuthorizeAction(t.Context(), "aws", req, []Provider{provider}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("AuthorizeAction returned err: %v", err)
	}
	if !called {
		t.Fatalf("AuthorizeAction did not invoke provider's AuthorizeAction")
	}
}

func TestAuthorizeAction_passesThroughWhenProviderDoesNotImplement(t *testing.T) {
	t.Parallel()

	provider := &fakeProviderNoActionAuth{name: "gcp"}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example/", nil)

	err := AuthorizeAction(t.Context(), "gcp", req, []Provider{provider}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("AuthorizeAction returned err for non-implementer: %v", err)
	}
}

func TestAuthorizeAction_unknownProviderReturnsError(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example/", nil)

	err := AuthorizeAction(t.Context(), "nope", req, []Provider{}, json.RawMessage(`{}`))
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("expected ErrUnknownProvider, got %v", err)
	}
}

func TestAuthorizeAction_propagatesActionAuthorizerError(t *testing.T) {
	t.Parallel()

	provider := &fakeAuthorizingProvider{
		name: "aws",
		authorizeAction: func(_ context.Context, _ *http.Request, _ json.RawMessage) error {
			return errors.New("action denied")
		},
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example/", nil)

	err := AuthorizeAction(t.Context(), "aws", req, []Provider{provider}, json.RawMessage(`{}`))

	if err == nil {
		t.Fatalf("expected error from ActionAuthorizer, got nil")
	}

	if !strings.Contains(err.Error(), "action denied") {
		t.Errorf("expected 'action denied' in error, got: %v", err)
	}
}

// TestAuthorizeAction_DispatchesAzure confirms the generic dispatch
// (auth.AuthorizeAction) calls an azure-named provider that implements
// ActionAuthorizer. No Azure-specific code in the dispatch itself is needed;
// azureProvider.AuthorizeAction is exercised by the azure_internal_test suite.
func TestAuthorizeAction_DispatchesAzure(t *testing.T) {
	t.Parallel()

	called := false
	prov := &fakeAuthorizingProvider{
		name: "azure",
		authorizeAction: func(_ context.Context, _ *http.Request, _ json.RawMessage) error {
			called = true
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://management.azure.com/x", nil)
	if err := AuthorizeAction(t.Context(), "azure", req, []Provider{prov}, nil); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}
	if !called {
		t.Error("azure ActionAuthorizer not dispatched")
	}
}

// fakeAuthorizingProvider satisfies both Provider and ActionAuthorizer.
type fakeAuthorizingProvider struct {
	name            string
	authorizeAction func(context.Context, *http.Request, json.RawMessage) error
}

func (f *fakeAuthorizingProvider) Name() string                                        { return f.name }
func (f *fakeAuthorizingProvider) Description() string                                 { return "" }
func (f *fakeAuthorizingProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }

func (f *fakeAuthorizingProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

func (f *fakeAuthorizingProvider) AuthorizeAction(ctx context.Context, req *http.Request, raw json.RawMessage) error {
	return f.authorizeAction(ctx, req, raw)
}

type fakeProviderNoActionAuth struct{ name string }

func (f *fakeProviderNoActionAuth) Name() string { return f.name }

func (f *fakeProviderNoActionAuth) Description() string { return "" }

func (f *fakeProviderNoActionAuth) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }

func (f *fakeProviderNoActionAuth) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

// TestAuthorizeAction_DispatchesGCP confirms that the generic dispatch
// (auth.AuthorizeAction) calls a gcp-named provider that implements
// ActionAuthorizer. No GCP-specific code in the dispatch itself is needed;
// gcpProvider.AuthorizeAction is exercised by the gcp_internal_test suite.
func TestAuthorizeAction_DispatchesGCP(t *testing.T) {
	t.Parallel()

	called := false
	prov := &fakeAuthorizingProvider{
		name: "gcp",
		authorizeAction: func(_ context.Context, _ *http.Request, _ json.RawMessage) error {
			called = true
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://compute.googleapis.com/x", nil)
	if err := AuthorizeAction(t.Context(), "gcp", req, []Provider{prov}, nil); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}
	if !called {
		t.Error("gcp ActionAuthorizer not dispatched")
	}
}

func TestAWSProvider_AuthorizeAction_nilActionProviderReturnsError(t *testing.T) {
	t.Parallel()
	p := newAWSProvider(aws.Config{}, func(_ context.Context) error { return nil })
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://s3.us-east-1.amazonaws.com/", nil)
	err := p.AuthorizeAction(t.Context(), req, json.RawMessage(`{}`))
	if err == nil {
		t.Errorf("expected error when actionProvider is nil")
	}
}

func TestAWSProvider_AuthorizeAction_delegatesToActionProvider(t *testing.T) {
	t.Parallel()
	p := newAWSProvider(aws.Config{}, func(_ context.Context) error { return nil })
	p.actionProvider = awshardening.NewProvider(
		&fakeActionRegistry{},
		fakeActionResolver{},
		&fakeActionEvaluator{allow: false},
		"arn:aws:iam::aws:policy/SecurityAudit",
	)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://s3.us-east-1.amazonaws.com/", nil)
	raw := json.RawMessage(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), req, raw)
	if !errors.Is(err, awshardening.ErrPolicyDenied) {
		t.Errorf("err = %v, want ErrPolicyDenied (delegated)", err)
	}
}

func noopSignHTTP(
	_ context.Context, _ aws.Credentials, _ *http.Request,
	_, _, _ string, _ time.Time,
) error {
	return nil
}

type fakeActionRegistry struct{}

func (fakeActionRegistry) Resolve(_ context.Context, _ string) ([]*awshardening.ServiceModel, error) {
	return []*awshardening.ServiceModel{{
		ARNNamespace:   "s3",
		EndpointPrefix: "s3",
		Protocol:       awshardening.ProtocolRestXML,
		Operations: map[string]awshardening.Operation{
			"ListBuckets": {HTTPMethod: "GET", URITemplate: "/"},
		},
	}}, nil
}

type fakeActionEvaluator struct{ allow bool }

func (e fakeActionEvaluator) AllowedAll(_ context.Context, _ []string) (bool, error) {
	return e.allow, nil
}

type fakeActionResolver struct{}

func (fakeActionResolver) Resolve(
	_ context.Context, _ *awshardening.ServiceModel, _ string,
) ([]string, awshardening.ActionSource) {
	return []string{"s3:ListBuckets"}, awshardening.SourceServiceRef
}

// --- Lazy-init tests for awsProvider: ensureReady / sync.Once contract. ---

func TestAWSProvider_lazyInit_notTriggeredAtConstruction(t *testing.T) {
	t.Parallel()
	var calls int
	p := newAWSProvider(aws.Config{}, func(_ context.Context) error {
		calls++
		return nil
	})
	_ = p
	if calls != 0 {
		t.Errorf("doLazyResolve called %d times at construction, want 0", calls)
	}
}

func TestAWSProvider_InjectAuth_triggersLazyOnce(t *testing.T) {
	t.Parallel()
	var calls int
	p := newAWSProvider(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.CredentialsProviderFunc(fakeAWSCreds),
	}, func(_ context.Context) error {
		calls++
		return nil
	})
	p.signHTTP = noopSignHTTP
	req := httptest.NewRequest(http.MethodGet, "https://s3.us-east-1.amazonaws.com/", nil)
	rawArgs := json.RawMessage(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	_ = p.InjectAuth(req, rawArgs)
	_ = p.InjectAuth(req, rawArgs)
	if calls != 1 {
		t.Errorf("doLazyResolve called %d times across 2 InjectAuth calls, want 1", calls)
	}
}

func TestAWSProvider_AuthorizeAction_triggersLazyOnce(t *testing.T) {
	t.Parallel()
	var calls int
	p := newAWSProvider(aws.Config{}, func(_ context.Context) error {
		calls++
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rawArgs := json.RawMessage(`{}`)
	_ = p.AuthorizeAction(t.Context(), req, rawArgs)
	_ = p.AuthorizeAction(t.Context(), req, rawArgs)
	if calls != 1 {
		t.Errorf("doLazyResolve called %d times across 2 AuthorizeAction calls, want 1", calls)
	}
}

func TestAWSProvider_AuthorizesHost_doesNotTriggerLazy(t *testing.T) {
	t.Parallel()
	var calls int
	p := newAWSProvider(aws.Config{}, func(_ context.Context) error {
		calls++
		return nil
	})
	rawArgs := json.RawMessage(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	_, _ = p.AuthorizesHost(t.Context(), "s3.us-east-1.amazonaws.com", rawArgs)
	if calls != 0 {
		t.Errorf("doLazyResolve called %d times during AuthorizesHost, want 0", calls)
	}
}

func TestAWSProvider_lazyInit_cachesFailure(t *testing.T) {
	t.Parallel()
	var calls int
	wantErr := errors.New("simulated init failure")
	p := newAWSProvider(aws.Config{}, func(_ context.Context) error {
		calls++
		return wantErr
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rawArgs := json.RawMessage(`{}`)

	err1 := p.InjectAuth(req, rawArgs)
	err2 := p.InjectAuth(req, rawArgs)

	if !errors.Is(err1, wantErr) {
		t.Errorf("err1 = %v, want wrapped %v", err1, wantErr)
	}
	if !errors.Is(err2, wantErr) {
		t.Errorf("err2 = %v, want wrapped %v", err2, wantErr)
	}
	if calls != 1 {
		t.Errorf("doLazyResolve called %d times, want 1 (failure cached)", calls)
	}
	if !strings.Contains(err1.Error(), "aws_hardening: not_ready") {
		t.Errorf("error not wrapped with not_ready prefix: %v", err1)
	}
}

func TestLazyInit_ensureReady_nilClosureReturnsError(t *testing.T) {
	t.Parallel()
	l := &lazyInit{prefix: "test_hardening"} //nolint:exhaustruct // nil doLazyResolve intentional.
	err := l.ensureReady(t.Context())
	if err == nil || !strings.Contains(err.Error(), "test_hardening: provider not wired (no doLazyResolve)") {
		t.Fatalf("expected not-wired error, got %v", err)
	}
}

func TestLazyInit_ensureReady_cachesSuccess(t *testing.T) {
	t.Parallel()
	calls := 0
	l := &lazyInit{ //nolint:exhaustruct // once/err zero.
		prefix:        "test_hardening",
		doLazyResolve: func(_ context.Context) error { calls++; return nil },
	}
	for range 3 {
		if err := l.ensureReady(t.Context()); err != nil {
			t.Fatalf("ensureReady = %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("doLazyResolve called %d times, want 1 (success cached)", calls)
	}
}

func TestLazyInit_ensureReady_cachesFailure(t *testing.T) {
	t.Parallel()
	calls := 0
	l := &lazyInit{ //nolint:exhaustruct // once/err zero.
		prefix:        "test_hardening",
		doLazyResolve: func(_ context.Context) error { calls++; return errors.New("init-failed") },
	}
	for range 3 {
		err := l.ensureReady(t.Context())
		if err == nil || !strings.Contains(err.Error(), "test_hardening: not_ready: init-failed") {
			t.Fatalf("expected wrapped not_ready error, got %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("doLazyResolve called %d times, want 1 (failure cached)", calls)
	}
}

func TestLazyInit_ensureReady_decouplesBootstrapFromCallerContext(t *testing.T) {
	t.Parallel()
	// The context state is captured INSIDE the resolve: ensureReady cancels the
	// bootstrap context once the resolve returns, so it can only be inspected live.
	var (
		errAtResolve error
		deadline     time.Time
		hasDeadline  bool
	)
	l := &lazyInit{ //nolint:exhaustruct // once/err zero.
		prefix:           "test_hardening",
		bootstrapTimeout: time.Hour,
		doLazyResolve: func(ctx context.Context) error {
			errAtResolve = ctx.Err()
			deadline, hasDeadline = ctx.Deadline()
			return nil
		},
	}
	// Caller context is already cancelled with no usable budget — the worst case a
	// short model-chosen request timeout produces. The one-time bootstrap must NOT
	// inherit that deadline/cancellation, or it would fail and cache the failure.
	callerCtx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := l.ensureReady(callerCtx); err != nil {
		t.Fatalf("ensureReady = %v", err)
	}
	if errAtResolve != nil {
		t.Fatalf("bootstrap context inherited caller cancellation: %v", errAtResolve)
	}
	if !hasDeadline || time.Until(deadline) < 30*time.Minute {
		t.Fatalf(
			"bootstrap deadline = %v ok=%t, want ~bootstrapTimeout in the future (decoupled)",
			deadline,
			hasDeadline,
		)
	}
}

func TestLazyInit_ensureReady_zeroBudgetUsesCallerContext(t *testing.T) {
	t.Parallel()
	var gotErr error
	l := &lazyInit{ //nolint:exhaustruct // bootstrapTimeout zero on purpose; once/err zero.
		prefix:        "test_hardening",
		doLazyResolve: func(ctx context.Context) error { gotErr = ctx.Err(); return nil },
	}
	// With no bootstrap budget configured the caller context passes through
	// unchanged (the behaviour test-only lazyInit constructions rely on).
	callerCtx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := l.ensureReady(callerCtx); err != nil {
		t.Fatalf("ensureReady = %v", err)
	}
	if !errors.Is(gotErr, context.Canceled) {
		t.Fatalf("bootstrap context err = %v, want context.Canceled (caller context passed through)", gotErr)
	}
}

func TestAWSProvider_AuthorizeAction_returnsLazyError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("init failed")
	p := newAWSProvider(aws.Config{}, func(_ context.Context) error {
		return wantErr
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rawArgs := json.RawMessage(`{}`)
	err := p.AuthorizeAction(t.Context(), req, rawArgs)
	if !errors.Is(err, wantErr) {
		t.Errorf("AuthorizeAction err = %v, want wrapped %v", err, wantErr)
	}
}

func TestEKSAuthorizeAction(t *testing.T) {
	t.Parallel()

	newProv := func() *eksProvider {
		p := newEKSProvider(aws.Config{Region: "us-east-1"}) //nolint:exhaustruct // region only.
		p.fetchView = func(_ context.Context, _ *EKSAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return k8sauthz.BuildViewPolicy([]k8sauthz.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
			}), nil
		}
		return p
	}

	rawArgs := json.RawMessage(`{"eks_auth":{"cluster_name":"c","region":"us-east-1"}}`)

	t.Run("allows list pods", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/namespaces/d/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); err != nil {
			t.Fatalf("list pods should be allowed: %v", err)
		}
	})

	t.Run("denies list secrets", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/namespaces/d/secrets", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("list secrets should be ErrForbidden, got %v", err)
		}
	})

	t.Run("fail closed on fetch error", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		p.fetchView = func(_ context.Context, _ *EKSAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return nil, errors.New("boom")
		}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); err == nil {
			t.Fatal("fetch error must deny (fail closed)")
		}
	})

	t.Run("requires cluster_name", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{}`)); err == nil {
			t.Fatal("missing cluster_name must error")
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{`)); err == nil {
			t.Fatal("malformed args must error")
		}
	})

	t.Run("denies write (POST pods)", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodPost, "https://example/api/v1/namespaces/d/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("POST pods should be ErrForbidden, got %v", err)
		}
	})

	t.Run("denies non-resource path", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/metrics", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("GET /metrics (non-resource) should be ErrForbidden, got %v", err)
		}
	})
}

func TestGKEAuthorizeAction(t *testing.T) {
	t.Parallel()

	newProv := func() *gkeProvider {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}) //nolint:exhaustruct // token only.
		p := newGKEProvider(ts)
		p.fetchView = func(_ context.Context, _ *GKEAuthArgs) (*k8sauthz.ViewPolicy, error) {
			rules := []k8sauthz.PolicyRule{{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get", "list", "watch"},
			}}
			return k8sauthz.BuildViewPolicy(rules), nil
		}
		return p
	}

	rawArgs := json.RawMessage(`{"gke_auth":{"cluster_name":"c","location":"us-central1","project":"p"}}`)

	t.Run("allows list deployments", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/apis/apps/v1/namespaces/d/deployments", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); err != nil {
			t.Fatalf("list deployments should be allowed: %v", err)
		}
	})

	t.Run("denies create deployments", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodPost, "https://example/apis/apps/v1/namespaces/d/deployments", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("create should be ErrForbidden, got %v", err)
		}
	})

	t.Run("denies secrets", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/namespaces/d/secrets", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("secrets should be ErrForbidden, got %v", err)
		}
	})

	t.Run("fail closed on fetch error", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		p.fetchView = func(_ context.Context, _ *GKEAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return nil, errors.New("boom")
		}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); err == nil {
			t.Fatal("fetch error must deny (fail closed)")
		}
	})

	t.Run("requires identifying args", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{}`)); err == nil {
			t.Fatal("missing gke args must error")
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{`)); err == nil {
			t.Fatal("malformed args must error")
		}
	})
}

func TestAKSAuthorizeAction(t *testing.T) {
	t.Parallel()

	newProv := func() *aksProvider {
		p := newAKSProvider(mockCredential(azcore.AccessToken{}, nil), cloud.Configuration{})
		p.fetchView = func(_ context.Context, _ *AKSAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return k8sauthz.BuildViewPolicy([]k8sauthz.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
			}), nil
		}
		return p
	}

	rawArgs := json.RawMessage(`{"aks_auth":{"cluster_name":"c","resource_group":"rg","subscription_id":"sub"}}`)

	t.Run("allows list pods", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); err != nil {
			t.Fatalf("list pods should be allowed: %v", err)
		}
	})

	t.Run("denies pods/exec", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodPost, "https://example/api/v1/namespaces/d/pods/web/exec", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("pods/exec should be ErrForbidden, got %v", err)
		}
	})

	t.Run("denies secrets", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/namespaces/d/secrets", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("secrets should be ErrForbidden, got %v", err)
		}
	})

	t.Run("fail closed on fetch error", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		p.fetchView = func(_ context.Context, _ *AKSAuthArgs) (*k8sauthz.ViewPolicy, error) {
			return nil, errors.New("boom")
		}
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); err == nil {
			t.Fatal("fetch error must deny (fail closed)")
		}
	})

	t.Run("requires identifying args", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(
			context.Background(), req,
			json.RawMessage(`{"aks_auth":{"cluster_name":"c"}}`),
		); err == nil {
			t.Fatal("missing resource_group and subscription_id must error")
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/api/v1/pods", nil)
		if err := p.AuthorizeAction(context.Background(), req, json.RawMessage(`{`)); err == nil {
			t.Fatal("malformed args must error")
		}
	})

	t.Run("denies non-resource path", func(t *testing.T) {
		t.Parallel()

		p := newProv()
		req, _ := http.NewRequest(http.MethodGet, "https://example/metrics", nil)
		if err := p.AuthorizeAction(context.Background(), req, rawArgs); !errors.Is(err, k8sauthz.ErrForbidden) {
			t.Fatalf("GET /metrics (non-resource) should be ErrForbidden, got %v", err)
		}
	})
}

func TestK8sProvidersImplementActionAuthorizer(t *testing.T) {
	t.Parallel()

	var (
		_ ActionAuthorizer = (*eksProvider)(nil)
		_ ActionAuthorizer = (*gkeProvider)(nil)
		_ ActionAuthorizer = (*aksProvider)(nil)
	)
}

// TestCloudProvidersRejectClusterAPIEndpoints pins the invariant that the gcp
// and azure providers' host-pinning layer rejects Kubernetes cluster API-server
// endpoints. These providers do not implement the k8s read-only gate; the only
// effective defense is that their AuthorizesHost refuses to admit k8s hosts at
// all. A regression here would silently bypass the gate for any GKE or AKS
// cluster reachable under auth_provider=gcp or auth_provider=azure.
func TestCloudProvidersRejectClusterAPIEndpoints(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// gcpProvider built with the same fake catalog used in gcp_internal_test.go.
	gcpProv := newTestGCPProvider(&fakeTokenSource{"tok"})

	// azureProvider built with the same fake catalog used in azure_internal_test.go.
	azureProv := newTestAzureProvider(fakeAzureCred{token: "tok"}, &fakeAzureAction{})

	t.Run("gcp rejects bare IP (GKE public endpoint)", func(t *testing.T) {
		t.Parallel()

		// GKE cluster API endpoints are commonly exposed as a bare public IP.
		ok, err := gcpProv.AuthorizesHost(ctx, "34.68.6.27",
			json.RawMessage(`{"gcp_auth":{"service":"container"}}`))
		if err == nil && ok {
			t.Fatal("SECURITY: gcp AuthorizesHost returned allowed for a bare IP cluster endpoint")
		}
	})

	t.Run("gcp rejects gke.goog DNS name (GKE private endpoint)", func(t *testing.T) {
		t.Parallel()

		// GKE Private Cluster API endpoints use the gke.goog domain.
		ok, err := gcpProv.AuthorizesHost(ctx, "something.us-central1-f.gke.goog",
			json.RawMessage(`{"gcp_auth":{"service":"container"}}`))
		if err == nil && ok {
			t.Fatal("SECURITY: gcp AuthorizesHost returned allowed for a gke.goog cluster endpoint")
		}
	})

	t.Run("azure rejects azmk8s.io DNS name (AKS cluster API server)", func(t *testing.T) {
		t.Parallel()

		// AKS cluster API servers use the hcp.<region>.azmk8s.io domain.
		ok, err := azureProv.AuthorizesHost(ctx, "yuri-aks-abc123.hcp.eastus.azmk8s.io",
			json.RawMessage(`{"azure_auth":{"service":"Microsoft.ContainerService"}}`))
		if err == nil && ok {
			t.Fatal("SECURITY: azure AuthorizesHost returned allowed for an azmk8s.io cluster endpoint")
		}
	})
}

func TestAWSAuthArgs_validate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		args    *AWSAuthArgs
		wantErr bool
	}{
		{"nil", nil, true},
		{"empty service", &AWSAuthArgs{}, true},
		{"ok", &AWSAuthArgs{Service: "s3", Region: "us-east-1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := c.args.validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("validate() err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestParseAWSArgs_BadJSON(t *testing.T) {
	t.Parallel()
	_, err := parseAWSArgs(json.RawMessage(`{bad`))
	if err == nil || !strings.Contains(err.Error(), "failed to parse aws_auth args") {
		t.Fatalf("parseAWSArgs bad json err=%v, want parse error", err)
	}
}

func TestEKSAuthArgs_validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		args    *EKSAuthArgs
		wantErr bool
	}{
		{"nil", nil, true},
		{"empty cluster", &EKSAuthArgs{}, true},
		{"ok", &EKSAuthArgs{ClusterName: "c"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if (c.args.validate() != nil) != c.wantErr {
				t.Fatalf("validate()=%v wantErr=%v", c.args.validate(), c.wantErr)
			}
		})
	}
}

func TestGKEAuthArgs_validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		args    *GKEAuthArgs
		wantErr bool
	}{
		{"nil", nil, true},
		{"only cluster", &GKEAuthArgs{ClusterName: "c"}, true},
		{"missing project", &GKEAuthArgs{ClusterName: "c", Location: "l"}, true},
		{"ok", &GKEAuthArgs{ClusterName: "c", Location: "l", Project: "p"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if (c.args.validate() != nil) != c.wantErr {
				t.Fatalf("validate()=%v wantErr=%v", c.args.validate(), c.wantErr)
			}
		})
	}
}

func TestEKSProvider_AuthorizesAddr(t *testing.T) {
	t.Parallel()

	newProvider := func(resolved []netip.Addr, resolveErr error) *eksProvider {
		return &eksProvider{ //nolint:exhaustruct // only the seams the pin reads.
			cfg: aws.Config{Region: "us-east-1"}, //nolint:exhaustruct // region only.
			describeCluster: func(_ context.Context, _ aws.Config, _ string) (clusterTLS, error) {
				return clusterTLS{host: "abc123.gr7.us-east-1.eks.amazonaws.com", caData: "Y2E="}, nil
			},
			resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return resolved, resolveErr
			},
		}
	}

	args := json.RawMessage(`{"eks_auth":{"cluster_name":"c"}}`)

	t.Run("allows an IP in the resolved set", func(t *testing.T) {
		t.Parallel()

		p := newProvider([]netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil)
		ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("203.0.113.7"), args)
		if err != nil || !ok {
			t.Fatalf("in-set IP: ok=%v err=%v, want true/nil", ok, err)
		}
	})

	t.Run("allows a private endpoint IP in the resolved set", func(t *testing.T) {
		t.Parallel()

		p := newProvider([]netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil)
		ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("10.0.0.5"), args)
		if err != nil || !ok {
			t.Fatalf("private in-set IP: ok=%v err=%v, want true/nil", ok, err)
		}
	})

	t.Run("denies an IP not in the resolved set", func(t *testing.T) {
		t.Parallel()

		p := newProvider([]netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil)
		ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("203.0.113.8"), args)
		if err != nil || ok {
			t.Fatalf("out-of-set IP: ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("fails closed on resolver error", func(t *testing.T) {
		t.Parallel()

		p := newProvider(nil, errors.New("dns boom"))
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("203.0.113.7"), args)
		if err == nil {
			t.Fatal("resolver error must deny (fail closed)")
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := newProvider(nil, nil)
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("203.0.113.7"), json.RawMessage(`{bad`))
		if err == nil {
			t.Fatal("malformed args must error")
		}
	})

	t.Run("requires cluster_name", func(t *testing.T) {
		t.Parallel()

		p := newProvider(nil, nil)
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("203.0.113.7"), json.RawMessage(`{}`))
		if err == nil {
			t.Fatal("missing cluster_name must error")
		}
	})

	t.Run("fails closed on cluster resolve error", func(t *testing.T) {
		t.Parallel()

		p := &eksProvider{ //nolint:exhaustruct // only the seams the pin reads.
			cfg: aws.Config{Region: "us-east-1"}, //nolint:exhaustruct // region only.
			describeCluster: func(_ context.Context, _ aws.Config, _ string) (clusterTLS, error) {
				return clusterTLS{}, errors.New("describe boom")
			},
			resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return nil, nil
			},
		}
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("203.0.113.7"), args)
		if err == nil {
			t.Fatal("cluster resolve error must deny (fail closed)")
		}
	})
}

// TestEKSProvider_AuthorizesAddr_FloorDeniesMetadata verifies the floor inside
// authorizesDialIP rejects cloud-metadata / host-local addresses even when a
// poisoned resolver returns them as the cluster endpoint — the IPv4 link-local
// metadata address, the AWS/GCP IPv6 host-local services (ULAs the floor
// otherwise permits), and the Azure WireServer platform IP.
func TestEKSProvider_AuthorizesAddr_FloorDeniesMetadata(t *testing.T) {
	t.Parallel()

	denied := []string{
		"169.254.169.254",    // AWS/GCP/Azure IPv4 IMDS (link-local).
		"fd00:ec2::254",      // AWS IPv6 IMDS (ULA).
		"fd00:ec2::23",       // AWS IPv6 EKS Pod Identity (ULA).
		"fd20:ce::254",       // GCP IPv6 metadata (ULA).
		"fd00:c1::a9fe:a9fe", // OCI IPv6 metadata (ULA, not enumerated — caught wholesale).
		"168.63.129.16",      // Azure WireServer (exact IPv4).
		"100.100.100.200",    // Alibaba ECS metadata (exact IPv4).
	}
	for _, ipStr := range denied {
		t.Run(ipStr, func(t *testing.T) {
			t.Parallel()

			ip := netip.MustParseAddr(ipStr)
			p := &eksProvider{ //nolint:exhaustruct // only the seams the pin reads.
				cfg: aws.Config{Region: "us-east-1"}, //nolint:exhaustruct // region only.
				describeCluster: func(_ context.Context, _ aws.Config, _ string) (clusterTLS, error) {
					return clusterTLS{host: "abc123.gr7.us-east-1.eks.amazonaws.com", caData: "Y2E="}, nil
				},
				resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
					return []netip.Addr{ip}, nil
				},
			}

			ok, err := p.AuthorizesAddr(context.Background(), ip, json.RawMessage(`{"eks_auth":{"cluster_name":"c"}}`))
			if err != nil || ok {
				t.Fatalf("%s must be floor-denied: ok=%v err=%v, want false/nil", ipStr, ok, err)
			}
		})
	}
}

func TestGKEProvider_AuthorizesAddr(t *testing.T) {
	t.Parallel()

	newProvider := func(host string) *gkeProvider {
		return &gkeProvider{ //nolint:exhaustruct // only the getCluster seam the pin reads.
			getCluster: func(_ context.Context, _ oauth2.TokenSource, _, _, _ string) (clusterTLS, error) {
				return clusterTLS{host: host, caData: "Z2tlLWNh"}, nil
			},
		}
	}

	args := json.RawMessage(`{"gke_auth":{"cluster_name":"c","location":"us-central1","project":"p"}}`)

	t.Run("allows the authoritative cloud IP", func(t *testing.T) {
		t.Parallel()

		ok, err := newProvider("34.71.1.2").AuthorizesAddr(context.Background(), netip.MustParseAddr("34.71.1.2"), args)
		if err != nil || !ok {
			t.Fatalf("matching cloud IP: ok=%v err=%v, want true/nil", ok, err)
		}
	})

	t.Run("denies a different IP", func(t *testing.T) {
		t.Parallel()

		ok, err := newProvider("34.71.1.2").AuthorizesAddr(
			context.Background(), netip.MustParseAddr("34.99.99.99"), args,
		)
		if err != nil || ok {
			t.Fatalf("mismatched IP: ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("fails closed when the host is not an IP literal", func(t *testing.T) {
		t.Parallel()

		// A DNS-based control-plane endpoint (GFE, public CA) is not IP-pinnable.
		p := newProvider("uid.us-central1.gke.goog")
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("34.71.1.2"), args)
		if err == nil {
			t.Fatal("non-IP host must fail closed")
		}
	})

	t.Run("floor denies a link-local dial IP", func(t *testing.T) {
		t.Parallel()

		ok, err := newProvider("34.71.1.2").AuthorizesAddr(
			context.Background(), netip.MustParseAddr("169.254.169.254"), args,
		)
		if err != nil || ok {
			t.Fatalf("link-local must be floor-denied: ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("requires identifying args", func(t *testing.T) {
		t.Parallel()

		p := newProvider("34.71.1.2")
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("34.71.1.2"), json.RawMessage(`{}`))
		if err == nil {
			t.Fatal("missing gke args must error")
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := newProvider("34.71.1.2")
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("34.71.1.2"), json.RawMessage(`{bad`))
		if err == nil {
			t.Fatal("malformed args must error")
		}
	})

	t.Run("fails closed on cluster resolve error", func(t *testing.T) {
		t.Parallel()

		p := &gkeProvider{ //nolint:exhaustruct // only the getCluster seam the pin reads.
			getCluster: func(_ context.Context, _ oauth2.TokenSource, _, _, _ string) (clusterTLS, error) {
				return clusterTLS{}, errors.New("gke resolve boom")
			},
		}
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("34.71.1.2"), args)
		if err == nil {
			t.Fatal("cluster resolve error must deny (fail closed)")
		}
	})
}

func TestAKSProvider_AuthorizesAddr(t *testing.T) {
	t.Parallel()

	newProvider := func(resolved []netip.Addr, resolveErr error) *aksProvider {
		kubeconfigB64 := base64.StdEncoding.EncodeToString([]byte(fakeKubeconfigToken()))
		srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterAdmin","value":"%s"}]}`, kubeconfigB64)
		})

		return &aksProvider{ //nolint:exhaustruct // only the seams the pin reads.
			credential: mockCredential(azcore.AccessToken{}, nil),
			newClient:  aksClientFor(srv.URL, srv.Client()),
			resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return resolved, resolveErr
			},
		}
	}

	args := json.RawMessage(
		`{"aks_auth":{"cluster_name":"my-cluster","resource_group":"my-rg","subscription_id":"sub-123"}}`,
	)

	t.Run("allows an IP in the resolved set", func(t *testing.T) {
		t.Parallel()

		p := newProvider([]netip.Addr{netip.MustParseAddr("20.1.2.3")}, nil)
		ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("20.1.2.3"), args)
		if err != nil || !ok {
			t.Fatalf("in-set IP: ok=%v err=%v, want true/nil", ok, err)
		}
	})

	t.Run("denies an IP not in the resolved set", func(t *testing.T) {
		t.Parallel()

		p := newProvider([]netip.Addr{netip.MustParseAddr("20.1.2.3")}, nil)
		ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("20.9.9.9"), args)
		if err != nil || ok {
			t.Fatalf("out-of-set IP: ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("fails closed on resolver error", func(t *testing.T) {
		t.Parallel()

		p := newProvider(nil, errors.New("dns boom"))
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("20.1.2.3"), args)
		if err == nil {
			t.Fatal("resolver error must deny (fail closed)")
		}
	})

	t.Run("floor denies link-local even if the resolver returns it", func(t *testing.T) {
		t.Parallel()

		p := newProvider([]netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil)
		ok, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("169.254.169.254"), args)
		if err != nil || ok {
			t.Fatalf("link-local must be floor-denied: ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("requires identifying fields", func(t *testing.T) {
		t.Parallel()

		// validation runs first; resolver/newClient seams are never reached.
		p := &aksProvider{
			credential: mockCredential(azcore.AccessToken{}, nil),
		} //nolint:exhaustruct // seams not needed.
		_, err := p.AuthorizesAddr(
			context.Background(), netip.MustParseAddr("20.1.2.3"),
			json.RawMessage(`{"aks_auth":{"cluster_name":"my-cluster"}}`),
		)
		if err == nil {
			t.Fatal("missing resource_group/subscription_id must error")
		}
	})

	t.Run("rejects malformed args", func(t *testing.T) {
		t.Parallel()

		p := &aksProvider{
			credential: mockCredential(azcore.AccessToken{}, nil),
		} //nolint:exhaustruct // parse fails first.
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("20.1.2.3"), json.RawMessage(`{bad`))
		if err == nil {
			t.Fatal("malformed args must error")
		}
	})

	t.Run("fails closed on cluster config error", func(t *testing.T) {
		t.Parallel()

		srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		p := &aksProvider{ //nolint:exhaustruct // only the seams needed for getClusterConfig to fail.
			credential: mockCredential(azcore.AccessToken{}, nil),
			newClient:  aksClientFor(srv.URL, srv.Client()),
			resolver: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("20.1.2.3")}, nil
			},
		}
		_, err := p.AuthorizesAddr(context.Background(), netip.MustParseAddr("20.1.2.3"), args)
		if err == nil {
			t.Fatal("cluster config error must deny (fail closed)")
		}
	})
}
