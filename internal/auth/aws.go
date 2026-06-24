package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	awshardening "github.com/cynative/cynative/internal/auth/aws"
)

const awsProviderName = "aws"

const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb924" +
	"27ae41e4649b934ca495991b7852b855"

// AWSAuthArgs holds AWS-specific authentication arguments for SigV4 signing.
type AWSAuthArgs struct {
	Service string `json:"service"          jsonschema_description:"AWS service SigV4 signing name (e.g. 's3', 'execute-api', or 'ecr' for the api.ecr.*.amazonaws.com endpoint). Required."` //nolint:lll // struct tags are indivisible
	Region  string `json:"region,omitempty" jsonschema_description:"AWS region for SigV4 signing (e.g. 'us-west-2'). Omit to derive the region from the request host."`                       //nolint:lll // struct tags are indivisible
}

// parseAWSArgs unmarshals the aws_auth arguments from the raw JSON. It returns
// the typed args (nil when the aws_auth key is absent), matching the sibling
// providers' nil convention; callers run validate to enforce required fields.
func parseAWSArgs(rawArgs json.RawMessage) (*AWSAuthArgs, error) {
	return parseAuthArgs[AWSAuthArgs](rawArgs, "aws_auth")
}

// validate fails closed unless the required SigV4 signing name (service) is set.
func (a *AWSAuthArgs) validate() error {
	if a == nil || a.Service == "" {
		return errors.New("aws_auth.service is required when using the AWS auth provider")
	}

	return nil
}

// signHTTPFunc signs an HTTP request with AWS SigV4.
type signHTTPFunc func(
	ctx context.Context,
	creds aws.Credentials,
	req *http.Request,
	payloadHash, service, region string,
	signingTime time.Time,
) error

// defaultAWSSignHTTP signs the request with the real AWS SigV4 signer.
func defaultAWSSignHTTP(
	ctx context.Context,
	creds aws.Credentials,
	req *http.Request,
	payloadHash, service, region string,
	signingTime time.Time,
) error {
	return v4signer.NewSigner().SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
}

type awsProvider struct {
	// lazyInit defers AWS initialization (credentials, action provider) to
	// first need. Defaulted by the shell in buildHardenedAWSProvider; tests
	// substitute a fake closure.
	lazyInit

	cfg            aws.Config
	signHTTP       signHTTPFunc
	actionProvider *awshardening.Provider
}

var (
	_ Provider         = (*awsProvider)(nil)
	_ ActionAuthorizer = (*awsProvider)(nil)
)

// newAWSProvider constructs an AWS provider with a closure that performs the
// one-time deferred AWS initialization on first need. The closure is invoked
// at most once by ensureReady via [sync.Once]. Tests substitute their own
// closure; the production wiring lives in buildHardenedAWSProvider.
func newAWSProvider(cfg aws.Config, doLazyResolve func(ctx context.Context) error) *awsProvider {
	return &awsProvider{ //nolint:exhaustruct // zero lazyInit.once + nil action fields are intentional.
		cfg:      cfg,
		signHTTP: defaultAWSSignHTTP,
		lazyInit: lazyInit{
			prefix:           "aws_hardening",
			bootstrapTimeout: hardeningBootstrapTimeout,
			doLazyResolve:    doLazyResolve,
		}, //nolint:exhaustruct // once/err zero.
	}
}

func (p *awsProvider) Name() string {
	return awsProviderName
}

func (p *awsProvider) Description() string {
	return "AWS API authentication (via AWS SDK). Discovers credentials from " +
		"environment variables, ~/.aws/credentials, or IAM roles. Signs requests using SigV4. " +
		"Requires aws_auth field."
}

func (p *awsProvider) InjectAuth(req *http.Request, rawArgs json.RawMessage) error {
	if err := p.ensureReady(req.Context()); err != nil {
		return err
	}

	awsArgs, err := parseAWSArgs(rawArgs)
	if err != nil {
		return err
	}
	if err = awsArgs.validate(); err != nil {
		return err
	}

	service := awsArgs.Service

	ctx := req.Context()

	// Sign under the host's canonical SigV4 signing name. It differs from the
	// claimed endpoint identifier for ECR et al. (host "api.ecr" → sign "ecr");
	// for every other service it equals the claim. Falls back to the claim when
	// the model archive cannot resolve the host.
	service = p.canonicalSigningName(ctx, req.URL.Hostname(), service)

	credentials, err := p.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	region := signingRegion(awsArgs, req, p.cfg.Region)

	payloadHash, err := getPayloadHash(req)
	if err != nil {
		return err
	}

	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	if err = p.signHTTP(ctx, credentials, req, payloadHash, service, region, time.Now()); err != nil {
		return fmt.Errorf("failed to sign AWS request: %w", err)
	}

	return nil
}

// signingRegion resolves the SigV4 signing region for a request. It is
// host-authoritative: for any parseable effective-authority host the region
// comes from the host (regional → the host's own region; global → the
// partition's canonical region), never from the model's claim, so an omitted or
// alias/cross-partition claim cannot mis-sign. Only an unparseable host falls
// back to the claim-or-SDK behavior. Verify (run before InjectAuth) guarantees a
// non-empty claim already equals a regional host's region.
func signingRegion(awsArgs *AWSAuthArgs, req *http.Request, sdkRegion string) string {
	host := strings.ToLower(awshardening.EffectiveAuthorityHost(req))
	ph, err := awshardening.ParseHost(host)
	if err != nil {
		return resolveRegion(awsArgs.Region, sdkRegion)
	}
	if ph.Region != "" {
		return ph.Region
	}
	return awshardening.CanonicalGlobalRegion(ph)
}

// AuthorizeAction implements the auth.ActionAuthorizer optional interface,
// delegating to the composed awshardening.Provider.
func (p *awsProvider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	if err := p.ensureReady(ctx); err != nil {
		return err
	}
	if p.actionProvider == nil {
		return errors.New("aws_hardening: action authorizer not initialized")
	}
	return p.actionProvider.AuthorizeAction(ctx, req, rawArgs)
}

func (p *awsProvider) AuthorizesHost(ctx context.Context, host string, rawArgs json.RawMessage) (bool, error) {
	awsArgs, err := parseAWSArgs(rawArgs)
	if err != nil {
		return false, err
	}
	if err = awsArgs.validate(); err != nil {
		return false, err
	}

	ph, err := awshardening.ParseHost(host)
	if err != nil {
		return false, err
	}
	verifyErr := awshardening.Verify(ph, awsArgs.Service, awsArgs.Region)
	if verifyErr == nil {
		return true, nil // claim matches the host's endpoint prefix (the common case).
	}

	// The claim may be the SigV4 signing name rather than the host's endpoint
	// prefix — they differ for ECR (claim "ecr" vs host "api.ecr") and a few
	// others. A same-service region mismatch gains nothing from resolution.
	if strings.EqualFold(awsArgs.Service, ph.Service) {
		return false, verifyErr
	}
	signingName, resolveErr := p.resolveSigningNameReady(ctx, host)
	if resolveErr != nil {
		return false, verifyErr // unresolved — surface the original host-claim mismatch.
	}
	if aliasErr := awshardening.Verify(
		awshardening.ParsedHost{Service: signingName, Region: ph.Region},
		awsArgs.Service, awsArgs.Region,
	); aliasErr != nil {
		return false, aliasErr
	}
	return true, nil
}

// resolveSigningNameReady ensures the deferred AWS init has run, then resolves
// the request host to its SigV4 signing name via the model archive.
func (p *awsProvider) resolveSigningNameReady(ctx context.Context, host string) (string, error) {
	if err := p.ensureReady(ctx); err != nil {
		return "", err
	}
	return p.resolveSigningName(ctx, host)
}

// resolveSigningName delegates host→signing-name resolution to the composed
// action provider's model archive. Callers must ensureReady first.
func (p *awsProvider) resolveSigningName(ctx context.Context, host string) (string, error) {
	if p.actionProvider == nil {
		return "", errors.New("aws_hardening: action provider not initialized")
	}
	return p.actionProvider.ResolveSigningName(ctx, host)
}

// canonicalSigningName returns the host's SigV4 signing name, falling back to
// claimed when the model archive cannot resolve it (unmodeled host, init not
// ready, or ambiguous collision) so signing never regresses below the claim.
// Self-contained: it ensures init has run rather than trusting the caller.
func (p *awsProvider) canonicalSigningName(ctx context.Context, host, claimed string) string {
	resolved, err := p.resolveSigningNameReady(ctx, host)
	if err != nil {
		return claimed
	}
	return resolved
}

// getPayloadHash computes the SHA-256 hex digest of the request body,
// returning [emptyPayloadSHA256] for nil bodies.  On success the body
// is rewound so it can still be read by the HTTP client.
func getPayloadHash(req *http.Request) (string, error) {
	if req.Body == nil {
		return emptyPayloadSHA256, nil
	}

	bodyBytes, err := io.ReadAll(req.Body)
	_ = req.Body.Close()

	if err != nil {
		return "", fmt.Errorf("failed to read request body for signing: %w", err)
	}

	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	hash := sha256.Sum256(bodyBytes)

	return hex.EncodeToString(hash[:]), nil
}
