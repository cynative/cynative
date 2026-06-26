package aws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	smithy "github.com/aws/smithy-go"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestDetectCredScope_fromCallerARN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		arn        string
		wantMode   CredScopeMode
		wantReason string
		wantRole   string
	}{
		{"arn:aws:iam::123456789012:user/alice", CredScopeDisabled, "", ""},
		{
			"arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
			CredScopeAssumeRole, "", "arn:aws:iam::123456789012:role/MyRole",
		},
		{"arn:aws:iam::123456789012:root", CredScopeDisabled, "", ""},
		{
			"arn:aws:sts::123456789012:federated-user/foo",
			CredScopeDisabled, "unsupported_credential_type:federated-user", "",
		},
		{"not-an-arn", CredScopeDisabled, "unrecognized_arn", ""},
		{"arn:aws:iam::123456789012:group/devs", CredScopeDisabled, "unrecognized_arn", ""},
		{"arn:aws:sts::123:assumed-role/JustRoleNoSlash", CredScopeDisabled, "unrecognized_arn", ""},
		{"arn:aws:sts::123:assumed-role//sess", CredScopeDisabled, "unrecognized_arn", ""},
		// Partition-awareness: GovCloud/China identities classify identically.
		{"arn:aws-us-gov:iam::123456789012:root", CredScopeDisabled, "", ""},
		{"arn:aws-cn:iam::123456789012:root", CredScopeDisabled, "", ""},
		{"arn:aws-us-gov:iam::123456789012:user/alice", CredScopeDisabled, "", ""},
		{
			"arn:aws-us-gov:sts::123456789012:assumed-role/MyRole/session-name",
			CredScopeAssumeRole, "", "arn:aws-us-gov:iam::123456789012:role/MyRole",
		},
	}
	for _, c := range cases {
		t.Run(c.arn, func(t *testing.T) {
			t.Parallel()
			got := DetectCredScope(c.arn)
			if got.Mode != c.wantMode {
				t.Errorf("Mode = %v, want %v", got.Mode, c.wantMode)
			}
			if got.Reason != c.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, c.wantReason)
			}
			if got.RoleARN != c.wantRole {
				t.Errorf("RoleARN = %q, want %q", got.RoleARN, c.wantRole)
			}
		})
	}
}

func TestDecodeAssumedRole_unrecognizedNoSeparator(t *testing.T) {
	t.Parallel()
	parsed, err := arn.Parse("arn:aws:sts::123:assumed-role/JustRoleNoSlash")
	if err != nil {
		t.Fatalf("arn.Parse: %v", err)
	}
	got := decodeAssumedRole(parsed)
	if got.Mode != CredScopeDisabled || got.Reason != "unrecognized_arn" {
		t.Errorf("got %+v, want Disabled+unrecognized_arn", got)
	}
}

func TestScopedProvider_AssumeRolePath(t *testing.T) {
	t.Parallel()
	var gotInput *sts.AssumeRoleInput
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			gotInput = in
			return &sts.AssumeRoleOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     aws.String("AK"),
					SecretAccessKey: aws.String("SK"),
					SessionToken:    aws.String("ST"),
					Expiration:      aws.Time(time.Now().Add(time.Hour)),
				},
			}, nil
		},
	}
	sp := &ScopedProvider{
		Mode:      CredScopeAssumeRole,
		RoleARN:   "arn:aws:iam::123:role/MyRole",
		PolicyARN: "arn:aws:iam::aws:policy/SecurityAudit",
		STS:       api,
		ErrOut:    nil,
	}
	if _, err := sp.Retrieve(t.Context()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if gotInput == nil || aws.ToString(gotInput.RoleArn) != "arn:aws:iam::123:role/MyRole" {
		t.Errorf("RoleArn not passed correctly: %+v", gotInput)
	}
	if len(gotInput.PolicyArns) != 1 ||
		aws.ToString(gotInput.PolicyArns[0].Arn) != "arn:aws:iam::aws:policy/SecurityAudit" {
		t.Errorf("PolicyArns not passed correctly: %+v", gotInput)
	}
	if gotInput.Policy != nil {
		t.Errorf("inline Policy must not be set, got %q", aws.ToString(gotInput.Policy))
	}
}

func TestScopedProvider_AssumeRoleError(t *testing.T) {
	t.Parallel()
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			return nil, errors.New("forbidden")
		},
	}
	sp := &ScopedProvider{Mode: CredScopeAssumeRole, STS: api, ErrOut: nil}
	_, err := sp.Retrieve(t.Context())
	if err == nil {
		t.Errorf("expected error from AssumeRole")
	}
}

func TestScopedProvider_DisabledPassthroughToBase(t *testing.T) {
	t.Parallel()
	base := &fakeBaseProvider{creds: aws.Credentials{AccessKeyID: "rawAK"}}
	sp := &ScopedProvider{Base: base, Mode: CredScopeDisabled, ErrOut: nil}
	creds, err := sp.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if creds.AccessKeyID != "rawAK" {
		t.Errorf("AccessKeyID = %q, want rawAK", creds.AccessKeyID)
	}
}

func TestScopedProvider_UnknownModeReturnsError(t *testing.T) {
	t.Parallel()
	sp := &ScopedProvider{Mode: CredScopeMode(99), ErrOut: nil}
	_, err := sp.Retrieve(t.Context())
	if err == nil {
		t.Errorf("expected error for unknown mode")
	}
}

func TestCredsFromSTS_NilExpiration(t *testing.T) {
	t.Parallel()
	got := credsFromSTS(&ststypes.Credentials{
		AccessKeyId:     aws.String("AK"),
		SecretAccessKey: aws.String("SK"),
		SessionToken:    aws.String("ST"),
	})
	if got.CanExpire {
		t.Errorf("CanExpire = true, want false when Expiration is nil")
	}
}

// --- New tests for degradation logic ---

func TestScopedProvider_AssumeRoleAccessDenied_degrades(t *testing.T) {
	t.Parallel()
	var assumeCalls int
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			assumeCalls++
			return nil, &fakeAPIError{code: "AccessDeniedException", message: "denied by trust policy"}
		},
	}
	base := &fakeBaseProvider{creds: aws.Credentials{AccessKeyID: "baseAK"}}
	var buf bytes.Buffer
	sp := &ScopedProvider{
		Base:      base,
		Mode:      CredScopeAssumeRole,
		RoleARN:   "arn:aws:iam::123:role/AWSReservedSSO_Foo",
		PolicyARN: "arn:aws:iam::aws:policy/SecurityAudit",
		STS:       api,
		ErrOut:    &buf,
	}

	creds, err := sp.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve after degrade: %v", err)
	}
	if creds.AccessKeyID != "baseAK" {
		t.Errorf("AccessKeyID = %q, want baseAK (fall-through to base)", creds.AccessKeyID)
	}
	if !sp.degraded.Load() {
		t.Errorf("degraded = false, want true")
	}
	if !strings.Contains(buf.String(), "aws_hardening: cred_scope degraded to disabled") {
		t.Errorf("degradation log missing: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "requests now run with full base AWS credentials") {
		t.Errorf("unscoped-credentials warning missing: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "reason=assume_role_unavailable:") {
		t.Errorf("reason missing: %q", buf.String())
	}

	// Second call must NOT re-attempt AssumeRole.
	if _, err2 := sp.Retrieve(t.Context()); err2 != nil {
		t.Fatalf("second Retrieve: %v", err2)
	}
	if assumeCalls != 1 {
		t.Errorf("AssumeRole called %d times, want 1", assumeCalls)
	}
}

func TestScopedProvider_AssumeRoleTransientError_doesNotDegrade(t *testing.T) {
	t.Parallel()
	var assumeCalls int
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			assumeCalls++
			return nil, errors.New("connection reset by peer")
		},
	}
	var buf bytes.Buffer
	sp := &ScopedProvider{
		Base:      &fakeBaseProvider{},
		Mode:      CredScopeAssumeRole,
		RoleARN:   "arn:aws:iam::123:role/MyRole",
		PolicyARN: "arn:aws:iam::aws:policy/SecurityAudit",
		STS:       api,
		ErrOut:    &buf,
	}

	if _, err := sp.Retrieve(t.Context()); err == nil {
		t.Error("expected transient error to propagate")
	}
	if sp.degraded.Load() {
		t.Error("transient error should not degrade")
	}
	if buf.Len() != 0 {
		t.Errorf("transient error should not log degradation: %q", buf.String())
	}

	// Second call still attempts AssumeRole.
	if _, err := sp.Retrieve(t.Context()); err == nil {
		t.Error("expected second transient error to propagate")
	}
	if assumeCalls != 2 {
		t.Errorf("AssumeRole called %d times, want 2", assumeCalls)
	}
}

func TestScopedProvider_PostDegradation_doesNotCallSTS(t *testing.T) {
	t.Parallel()
	var assumeCalls int
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			assumeCalls++
			return nil, &fakeAPIError{code: "AccessDenied", message: "denied"}
		},
	}
	sp := &ScopedProvider{
		Base:      &fakeBaseProvider{},
		Mode:      CredScopeAssumeRole,
		RoleARN:   "arn:aws:iam::123:role/MyRole",
		PolicyARN: "arn:aws:iam::aws:policy/SecurityAudit",
		STS:       api,
		ErrOut:    nil, // nil writer must be safe
	}

	const retrieveCount = 5
	for i := range retrieveCount {
		if _, err := sp.Retrieve(t.Context()); err != nil {
			t.Fatalf("Retrieve #%d: %v", i, err)
		}
	}
	if assumeCalls != 1 {
		t.Errorf("AssumeRole called %d times across %d Retrieves, want 1", assumeCalls, retrieveCount)
	}
}

func TestScopedProvider_ConcurrentFirstTouch_singleDegradationLog(t *testing.T) {
	t.Parallel()
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			return nil, &fakeAPIError{code: "AccessDeniedException", message: "denied"}
		},
	}
	var buf bytes.Buffer
	// concurrentWriter serializes writes via a mutex so concurrent Fprintf
	// calls don't interleave bytes (bytes.Buffer is not safe for concurrent use).
	w := &concurrentWriter{out: &buf}
	sp := &ScopedProvider{
		Base:      &fakeBaseProvider{},
		Mode:      CredScopeAssumeRole,
		RoleARN:   "arn:aws:iam::123:role/MyRole",
		PolicyARN: "arn:aws:iam::aws:policy/SecurityAudit",
		STS:       api,
		ErrOut:    w,
	}

	var wg sync.WaitGroup
	const concurrentRetrieves = 20
	for range concurrentRetrieves {
		wg.Go(func() {
			_, _ = sp.Retrieve(t.Context())
		})
	}
	wg.Wait()

	if got := strings.Count(buf.String(), "aws_hardening: cred_scope degraded"); got != 1 {
		t.Errorf("degradation log emitted %d times, want 1; full output:\n%s", got, buf.String())
	}
}

func TestIsAccessDenied_classification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain string", errors.New("boom"), false},
		{
			"smithy APIError with code AccessDenied",
			&fakeAPIError{code: "AccessDenied", message: "denied"},
			true,
		},
		{
			"smithy APIError with code AccessDeniedException",
			&fakeAPIError{code: "AccessDeniedException", message: "denied"},
			true,
		},
		{
			"smithy APIError with other code",
			&fakeAPIError{code: "ThrottlingException", message: "slow down"},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := isAccessDenied(c.err); got != c.want {
				t.Errorf("isAccessDenied(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// --- ResolveScope tests ---

func TestResolveScope_AssumeRoleDenied_disables(t *testing.T) {
	t.Parallel()
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			return nil, &fakeAPIError{code: "AccessDenied", message: "denied"}
		},
	}
	dec := DetectCredScope("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Foo/sess")
	res := ResolveScope(t.Context(), dec, api, "arn:aws:iam::aws:policy/SecurityAudit",
		&fakeBaseProvider{creds: aws.Credentials{AccessKeyID: "baseAK"}}, nil)
	if res.Mode != CredScopeDisabled || res.Reason != reasonAssumeRoleUnavailable {
		t.Fatalf("got mode=%v reason=%q, want disabled/assume_role_unavailable", res.Mode, res.Reason)
	}
	if res.Credentials == nil {
		t.Fatal("Credentials must not be nil")
	}
	if res.Verified {
		t.Error("Verified must be false on degrade")
	}
}

func TestResolveScope_Transient_keepsDecidedMode(t *testing.T) {
	t.Parallel()
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			return nil, errors.New("connection reset by peer")
		},
	}
	dec := DetectCredScope("arn:aws:sts::123456789012:assumed-role/MyRole/sess")
	res := ResolveScope(t.Context(), dec, api, "arn:aws:iam::aws:policy/SecurityAudit",
		&fakeBaseProvider{}, nil)
	if res.Mode != CredScopeAssumeRole || res.Reason != "" {
		t.Fatalf("transient must keep decided mode, got %v/%q", res.Mode, res.Reason)
	}
	if res.Credentials == nil {
		t.Fatal("Credentials must not be nil")
	}
	if res.Verified {
		t.Error("Verified must be false on transient error (unconfirmed)")
	}
}

func TestResolveScope_Disabled_passthrough(t *testing.T) {
	t.Parallel()
	dec := DetectCredScope("arn:aws:sts::123456789012:federated-user/u") // → Disabled.
	res := ResolveScope(t.Context(), dec, &stsAPIMock{}, "arn:aws:iam::aws:policy/SecurityAudit",
		&fakeBaseProvider{}, nil)
	if res.Mode != CredScopeDisabled || res.Credentials == nil {
		t.Fatalf("disabled decision must pass through with a chain, got %v", res)
	}
	if res.Verified {
		t.Error("Verified must be false on disabled passthrough")
	}
}

func TestResolveScope_Success_keepsDecidedMode(t *testing.T) {
	t.Parallel()
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			return &sts.AssumeRoleOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     aws.String("scopedAK"),
					SecretAccessKey: aws.String("scopedSK"),
					SessionToken:    aws.String("scopedST"),
				},
			}, nil
		},
	}
	dec := DetectCredScope("arn:aws:sts::123456789012:assumed-role/MyRole/sess")
	res := ResolveScope(t.Context(), dec, api, "arn:aws:iam::aws:policy/SecurityAudit",
		&fakeBaseProvider{creds: aws.Credentials{AccessKeyID: "baseAK"}}, nil)
	if res.Mode != CredScopeAssumeRole || res.Reason != "" {
		t.Fatalf("success must keep decided mode, got %v/%q", res.Mode, res.Reason)
	}
	if res.Credentials == nil {
		t.Fatal("Credentials must not be nil")
	}
	if !res.Verified {
		t.Error("Verified must be true on successful eager probe")
	}
}

// TestResolveScope_EagerDegrade_isSilent pins that an eager-probe degrade
// (definitive AccessDenied at registration) emits NO log even when an errOut is
// provided: the enforced=client token in the startup inventory and the stderr
// aws_hardening notice already surface that signal, so logging here too would be
// redundant.
func TestResolveScope_EagerDegrade_isSilent(t *testing.T) {
	t.Parallel()
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			return nil, &fakeAPIError{code: "AccessDenied", message: "denied"}
		},
	}
	dec := DetectCredScope("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Foo/sess")
	var buf bytes.Buffer
	res := ResolveScope(t.Context(), dec, api, "arn:aws:iam::aws:policy/SecurityAudit",
		&fakeBaseProvider{creds: aws.Credentials{AccessKeyID: "baseAK"}}, &buf)
	if res.Mode != CredScopeDisabled || res.Reason != reasonAssumeRoleUnavailable {
		t.Fatalf("got mode=%v reason=%q, want disabled/assume_role_unavailable", res.Mode, res.Reason)
	}
	if buf.Len() != 0 {
		t.Errorf("eager degrade must be silent (enforced=client in inventory carries the signal), got %q", buf.String())
	}
}

// TestResolveScope_ArmsRequestTimeDegradeLog pins that when the eager probe does
// NOT degrade (here: a transient error), ResolveScope arms the request-time
// stderr writer so a LATER (lazy) degrade — the only runtime signal in that
// window — still reaches the operator.
func TestResolveScope_ArmsRequestTimeDegradeLog(t *testing.T) {
	t.Parallel()
	var calls int
	api := &stsAPIMock{
		AssumeRoleFunc: func(
			_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options),
		) (*sts.AssumeRoleOutput, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("connection reset by peer") // transient: no eager degrade.
			}
			return nil, &fakeAPIError{code: "AccessDenied", message: "denied"} // request-time degrade.
		},
	}
	dec := DetectCredScope("arn:aws:sts::123456789012:assumed-role/MyRole/sess")
	var buf bytes.Buffer
	res := ResolveScope(t.Context(), dec, api, "arn:aws:iam::aws:policy/SecurityAudit",
		&fakeBaseProvider{creds: aws.Credentials{AccessKeyID: "baseAK"}}, &buf)
	// Eager probe was transient → unverified, not degraded, nothing logged yet.
	if res.Mode != CredScopeAssumeRole || res.Verified {
		t.Fatalf("transient eager probe: got mode=%v verified=%v, want assume_role/false", res.Mode, res.Verified)
	}
	if buf.Len() != 0 {
		t.Fatalf("eager probe must not log on a transient error, got %q", buf.String())
	}
	// A request-time Retrieve now hits AccessDenied → lazy degrade → must log.
	creds, err := res.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("request-time Retrieve after degrade: %v", err)
	}
	if creds.AccessKeyID != "baseAK" {
		t.Errorf("AccessKeyID = %q, want baseAK (fall-through to base)", creds.AccessKeyID)
	}
	if !strings.Contains(buf.String(), "aws_hardening: cred_scope degraded to disabled") {
		t.Errorf("request-time degrade log missing: %q", buf.String())
	}
}

// --- helpers ---

type fakeBaseProvider struct{ creds aws.Credentials }

func (f *fakeBaseProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return f.creds, nil
}

type concurrentWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *concurrentWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.out.Write(p)
}

type fakeAPIError struct {
	code    string
	message string
}

func (e *fakeAPIError) Error() string                 { return e.code + ": " + e.message }
func (e *fakeAPIError) ErrorCode() string             { return e.code }
func (e *fakeAPIError) ErrorMessage() string          { return e.message }
func (e *fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }
