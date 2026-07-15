package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	smithy "github.com/aws/smithy-go"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

//go:generate go tool moq -out sts_mock_test.go . stsAPI

// CredScopeMode identifies how credential scoping operates for this run.
// Determined once at provider construction from the caller's STS:GetCallerIdentity ARN.
type CredScopeMode int

const (
	CredScopeDisabled CredScopeMode = iota
	CredScopeAssumeRole
)

// reasonAssumeRoleUnavailable is the machine-readable reason an assumed-role
// scope degraded to disabled. It surfaces as the enforced=client token in the
// startup inventory and in the request-time degrade log, so it is pinned as a
// constant.
const reasonAssumeRoleUnavailable = "assume_role_unavailable"

// reasonUnrecognizedARN is the machine-readable reason a caller ARN could not
// be classified (unparseable, malformed, or an unrecognized identity shape).
const reasonUnrecognizedARN = "unrecognized_arn"

// ARN service namespaces DetectCredScope classifies caller identities by.
const (
	arnServiceIAM = "iam"
	arnServiceSTS = "sts"
)

// CredScopeDecision is the result of DetectCredScope: the chosen mode plus
// (for assumed-role) the derived role ARN to assume, and (on a disabled
// classification) a machine-readable Reason for the posture log.
type CredScopeDecision struct {
	Mode    CredScopeMode
	RoleARN string
	Reason  string
}

// DetectCredScope classifies callerARN (the Arn field from sts:GetCallerIdentity)
// and returns the appropriate CredScopeDecision. Assumed-role identities are
// re-scoped via STS AssumeRole; every other identity type — IAM user, root,
// federated-user, and anything unrecognized — runs with its base credentials
// (CredScopeDisabled) and is gated solely by the host-pinning and action
// (iam:SimulateCustomPolicy) layers. (A GetFederationToken session, the former
// scoping path for IAM-user/root, cannot call IAM at all, which defeats the
// connector's purpose.) It still parses the ARN partition (aws, aws-us-gov,
// aws-cn) so an assumed-role self-assumption targets the caller's own partition
// and account. Pure: no I/O.
func DetectCredScope(callerARN string) CredScopeDecision {
	parsed, err := arn.Parse(callerARN)
	if err != nil {
		return CredScopeDecision{Mode: CredScopeDisabled, Reason: reasonUnrecognizedARN}
	}
	switch {
	case parsed.Service == arnServiceIAM &&
		(parsed.Resource == "root" || strings.HasPrefix(parsed.Resource, "user/")):
		return CredScopeDecision{Mode: CredScopeDisabled}
	case parsed.Service == arnServiceSTS && strings.HasPrefix(parsed.Resource, "assumed-role/"):
		return decodeAssumedRole(parsed)
	case parsed.Service == arnServiceSTS && strings.HasPrefix(parsed.Resource, "federated-user/"):
		return CredScopeDecision{Mode: CredScopeDisabled, Reason: "unsupported_credential_type:federated-user"}
	default:
		return CredScopeDecision{Mode: CredScopeDisabled, Reason: reasonUnrecognizedARN}
	}
}

// decodeAssumedRole derives the assumable role ARN from a parsed assumed-role
// caller ARN (resource "assumed-role/RoleName/SessionName"), preserving the
// caller's partition and account so the self-assume target is correct in every
// partition. Fails closed (unrecognized) on a malformed resource.
func decodeAssumedRole(parsed arn.ARN) CredScopeDecision {
	roleAndSession := strings.TrimPrefix(parsed.Resource, "assumed-role/")
	role, _, sepFound := strings.Cut(roleAndSession, "/")
	if !sepFound || role == "" {
		return CredScopeDecision{Mode: CredScopeDisabled, Reason: reasonUnrecognizedARN}
	}
	roleARN := arn.ARN{
		Partition: parsed.Partition,
		Service:   arnServiceIAM,
		Region:    "",
		AccountID: parsed.AccountID,
		Resource:  "role/" + role,
	}.String()
	return CredScopeDecision{Mode: CredScopeAssumeRole, RoleARN: roleARN}
}

// stsAPI is the subset of *sts.Client we depend on. Mocked in tests.
type stsAPI interface {
	AssumeRole(
		ctx context.Context, in *sts.AssumeRoleInput, opts ...func(*sts.Options),
	) (*sts.AssumeRoleOutput, error)
}

// ScopedProvider implements aws.CredentialsProvider, wrapping a base provider
// with credential scoping via STS AssumeRole. On a definitive AccessDenied
// it permanently degrades to CredScopeDisabled for the process lifetime.
type ScopedProvider struct {
	Base      aws.CredentialsProvider
	Mode      CredScopeMode
	RoleARN   string
	PolicyARN string
	STS       stsAPI
	// ErrOut receives the one-line operator degradation notice. A nil writer means
	// silent: ResolveScope leaves it nil for the eager probe (a degrade there is
	// already surfaced by the inventory sts= column) and arms it only for the
	// request-time path, where a lazy degrade is the sole runtime signal. In
	// production the shell passes os.Stderr; tests inject a bytes.Buffer.
	ErrOut io.Writer

	degraded    atomic.Bool // true after one AccessDenied; serves all subsequent reads.
	degradeOnce sync.Once   // emits the degradation log exactly once.
}

const sessionDuration = int32(3600) // 1 hour cap (AssumeRole self-chain limit).

// Retrieve implements aws.CredentialsProvider. In CredScopeAssumeRole mode it
// attempts to vend scoped credentials and, on a definitive AccessDenied,
// permanently degrades to unscoped base credentials (logging once); transient
// throttling/freshness errors propagate unchanged (no degrade on a blip). In
// CredScopeDisabled mode it returns the base credentials unchanged. A prior
// degrade routes straight to CredScopeDisabled.
func (p *ScopedProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	mode := p.Mode
	if p.degraded.Load() {
		mode = CredScopeDisabled
	}

	switch mode {
	case CredScopeAssumeRole:
		creds, err := p.assumeRole(ctx)
		if err == nil {
			return creds, nil
		}
		if !isAccessDenied(err) {
			return aws.Credentials{}, err
		}
		p.degraded.Store(true)
		p.degradeOnce.Do(func() {
			if p.ErrOut != nil {
				fmt.Fprintf(p.ErrOut,
					"⚠️ aws_hardening: cred_scope degraded to disabled (reason=%s: %s) — "+
						"requests now run with full base AWS credentials, no longer scoped to %s\n",
					reasonAssumeRoleUnavailable,
					cloudauth.ShortenError(err, cloudauth.DefaultMaxErrorLen), p.PolicyARN)
			}
		})
		return p.Base.Retrieve(ctx)
	case CredScopeDisabled:
		return p.Base.Retrieve(ctx)
	}
	return aws.Credentials{}, fmt.Errorf("ScopedProvider: unknown CredScopeMode %v", mode)
}

// codeAccessDenied and codeAccessDeniedException are the smithy API error codes
// for a definitive AWS authorization denial.
const (
	codeAccessDenied          = "AccessDenied"
	codeAccessDeniedException = "AccessDeniedException"
)

// isAccessDenied reports whether err is a definitive AWS authorization denial
// (a smithy.APIError whose code is "AccessDenied" or "AccessDeniedException").
// It is the sole trigger for credential-scoping degradation; transient errors
// (throttling, expired token, network) return false so they propagate instead.
func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		code := apiErr.ErrorCode()
		return code == codeAccessDenied || code == codeAccessDeniedException
	}
	return false
}

// ScopeResult is the eager credential-scope resolution: the effective mode after
// one scope attempt, a machine-readable degrade Reason (set only when the attempt
// definitively degraded the decided mode to disabled), the scoped credential
// chain to reuse as the session's credentials (cached so the eagerly-minted STS
// creds are not discarded), and Verified — true only when the eager probe actually
// confirmed the scope (chain.Retrieve succeeded without degradation). It is false
// on disabled-passthrough, degrade, and transient paths so the posture label can
// distinguish "confirmed" from "unverified (assumed)".
type ScopeResult struct {
	Mode        CredScopeMode
	Reason      string
	Credentials aws.CredentialsProvider
	Verified    bool
}

// ResolveScope (exported so the parent auth-package shell wrapper can call it)
// performs ONE eager scope attempt for the decided mode and reports the effective
// mode plus the reusable scoped chain. A definitive AccessDenied for an
// assumed-role identity yields CredScopeDisabled + reason; a transient error
// keeps the decided mode — the request-time path resolves the real scope later,
// and AWS stays available either way. The returned Credentials always wraps the
// ScopedProvider so the minted creds are the session creds (reused, not discarded).
func ResolveScope(
	ctx context.Context, decision CredScopeDecision, stsClient stsAPI,
	policyARN string, base aws.CredentialsProvider, errOut io.Writer,
) ScopeResult {
	scoped := &ScopedProvider{ //nolint:exhaustruct // degraded/degradeOnce zero-valued.
		Base: base, Mode: decision.Mode, RoleARN: decision.RoleARN,
		// ErrOut stays nil for the eager probe below: a degrade here is already
		// surfaced by the enforced=client token in the startup inventory and the
		// stderr aws_hardening notice, so logging it again here would be redundant.
		// It is armed to errOut only if the probe does NOT degrade, so a later
		// request-time (lazy) degrade still reaches the operator.
		PolicyARN: policyARN, STS: stsClient, ErrOut: nil,
	}
	chain := aws.NewCredentialsCache(scoped)
	if decision.Mode == CredScopeDisabled {
		// Disabled passthrough: no probe attempted, not verified.
		return ScopeResult{Mode: CredScopeDisabled, Reason: decision.Reason, Credentials: chain}
	}
	_, err := chain.Retrieve(ctx)
	// ScopedProvider degrades internally on AccessDenied (sets degraded=true and
	// falls back to base creds, returning nil error). Check the degraded flag first.
	if scoped.degraded.Load() {
		// Definitive eager degrade: scope confirmed unavailable → disabled, not
		// verified. Left silent (ErrOut nil); the sts= column carries the signal.
		return ScopeResult{Mode: CredScopeDisabled, Reason: reasonAssumeRoleUnavailable, Credentials: chain}
	}
	// Eager probe did not degrade. Arm the request-time degrade log: this write
	// happens during single-threaded registration, before the chain is shared with
	// request goroutines, so a later lazy degrade logs exactly once to errOut.
	scoped.ErrOut = errOut
	if err != nil {
		// Transient error: keep the decided mode label but mark unverified — the
		// request-time ScopedProvider resolves the true scope later.
		return ScopeResult{Mode: decision.Mode, Reason: "", Credentials: chain, Verified: false}
	}
	// Eager probe succeeded: scope is confirmed.
	return ScopeResult{Mode: decision.Mode, Reason: "", Credentials: chain, Verified: true}
}

func (p *ScopedProvider) assumeRole(ctx context.Context) (aws.Credentials, error) {
	out, err := p.STS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(p.RoleARN),
		RoleSessionName: aws.String("cynative"),
		DurationSeconds: aws.Int32(sessionDuration),
		PolicyArns: []ststypes.PolicyDescriptorType{
			{Arn: aws.String(p.PolicyARN)},
		},
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("AssumeRole: %w", err)
	}
	return credsFromSTS(out.Credentials), nil
}

func credsFromSTS(c *ststypes.Credentials) aws.Credentials {
	creds := aws.Credentials{
		AccessKeyID:     aws.ToString(c.AccessKeyId),
		SecretAccessKey: aws.ToString(c.SecretAccessKey),
		SessionToken:    aws.ToString(c.SessionToken),
		Source:          "cynative-scoped",
		CanExpire:       c.Expiration != nil,
	}
	if c.Expiration != nil {
		creds.Expires = *c.Expiration
	}
	return creds
}
