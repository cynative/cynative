package aws

import (
	"context"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/cache"
)

type fakeSRGetter struct {
	model *ServiceRefModel
}

func (f *fakeSRGetter) Get(context.Context, string) *ServiceRefModel { return f.model }

type fakeDSLookuper struct {
	actions    []string
	gotSDK     []string
	sdkActions map[string][]string // op -> actions for LookupSDKID.
	gotSDKID   string
}

func (f *fakeDSLookuper) Lookup(_ context.Context, _ string, sdkNames []string, _ string) []string {
	f.gotSDK = sdkNames
	return f.actions
}

func (f *fakeDSLookuper) LookupSDKID(_ context.Context, sdkID, op string) []string {
	f.gotSDKID = sdkID
	return f.sdkActions[op]
}

// erroringServiceRef always misses, exercising the fail-closed fall-through: an
// unavailable Service Reference must never authorize an action.
type erroringServiceRef struct{}

func (erroringServiceRef) Get(context.Context, string) *ServiceRefModel { return nil }

func srModel(op string, acts []string, sdk []string) *ServiceRefModel {
	return &ServiceRefModel{Service: "s3", Operations: map[string]SROperation{
		op: {AuthorizedActions: acts, SDKNames: sdk},
	}}
}

func TestActionResolver_PermissionlessShortCircuits(t *testing.T) {
	t.Parallel()
	// A permissionless op (e.g. sts:GetCallerIdentity) needs no IAM permission,
	// so the resolver must short-circuit to SourcePermissionless rather than
	// resolving an action that the scoping policy would then wrongly deny. The
	// Service Reference getter here would otherwise yield a SourceServiceRef
	// action, proving the permissionless check takes precedence.
	sr := &fakeSRGetter{
		model: srModel("GetCallerIdentity", []string{"sts:GetCallerIdentity"}, nil),
	}
	ds := &fakeDSLookuper{actions: nil, gotSDK: nil}
	r := NewActionResolver(sr, ds)
	model := &ServiceModel{ARNNamespace: "sts", Dir: "sts", EndpointPrefix: "sts"}
	acts, src := r.Resolve(t.Context(), model, "GetCallerIdentity")
	if src != SourcePermissionless || acts != nil {
		t.Errorf("Resolve = (%v, %v), want (nil, SourcePermissionless)", acts, src)
	}
}

func TestActionResolver_pinnedPermissionless(t *testing.T) {
	t.Parallel()
	// sts:GetCallerIdentity is the only pinned permissionless op. It is recognized
	// without any data tier: an erroring Service Reference and an empty iam-dataset
	// must not change the outcome, proving the check is deterministic and
	// network-free.
	r := NewActionResolver(erroringServiceRef{}, &fakeDSLookuper{actions: nil, gotSDK: nil})
	stsModel := &ServiceModel{ARNNamespace: "sts", Dir: "sts", EndpointPrefix: "sts"}
	acts, src := r.Resolve(t.Context(), stsModel, "GetCallerIdentity")
	if src != SourcePermissionless || acts != nil {
		t.Errorf("Resolve(sts, GetCallerIdentity) = (%v, %v), want (nil, SourcePermissionless)", acts, src)
	}
	// Deliberately EXCLUDED no-permission ops must fall through to action resolution
	// (and be denied by a read-only policy), never short-circuit. sts:GetSessionToken
	// issues credentials; dynamodb:DescribeEndpoints is not needed by cynative. These
	// guard against re-adding an unjustified credential or metadata bypass.
	if _, s := r.Resolve(t.Context(), stsModel, "GetSessionToken"); s == SourcePermissionless {
		t.Error("GetSessionToken short-circuited; a credential-issuing op must not bypass the gate")
	}
	dynamoModel := &ServiceModel{ARNNamespace: "dynamodb", Dir: "dynamodb", EndpointPrefix: "dynamodb"}
	if _, s := r.Resolve(t.Context(), dynamoModel, "DescribeEndpoints"); s == SourcePermissionless {
		t.Error("DescribeEndpoints short-circuited; it is not pinned and must be policy-checked")
	}
}

func TestActionResolver_tier1ServiceRef(t *testing.T) {
	t.Parallel()
	r := NewActionResolver(
		&fakeSRGetter{
			model: srModel("ListBuckets", []string{"s3:ListAllMyBuckets"}, nil),
		},
		&fakeDSLookuper{actions: nil, gotSDK: nil},
	)
	model := &ServiceModel{ARNNamespace: "s3", Dir: "s3", EndpointPrefix: "s3"}
	got, src := r.Resolve(t.Context(), model, "ListBuckets")
	if src != SourceServiceRef {
		t.Errorf("src = %v, want SourceServiceRef", src)
	}
	if len(got) != 1 || got[0] != "s3:ListAllMyBuckets" {
		t.Errorf("actions = %v, want [s3:ListAllMyBuckets]", got)
	}
}

func TestActionResolver_tier2IAMDatasetWhenServiceRefEmpty(t *testing.T) {
	t.Parallel()
	ds := &fakeDSLookuper{actions: []string{"s3:PutLifecycleConfiguration"}, gotSDK: nil}
	r := NewActionResolver(
		&fakeSRGetter{model: srModel("PutBucketLifecycleConfiguration", nil, []string{"s3", "s3control"})},
		ds,
	)
	model := &ServiceModel{ARNNamespace: "s3", Dir: "s3", EndpointPrefix: "s3"}
	got, src := r.Resolve(t.Context(), model, "PutBucketLifecycleConfiguration")
	if src != SourceIAMDataset {
		t.Errorf("src = %v, want SourceIAMDataset", src)
	}
	if len(got) != 1 || got[0] != "s3:PutLifecycleConfiguration" {
		t.Errorf("actions = %v", got)
	}
	if want := []string{"s3", "s3control"}; !equalStrings(ds.gotSDK, want) {
		t.Errorf("dataset got sdkNames %v, want %v", ds.gotSDK, want)
	}
}

func TestActionResolver_tier3DeriveWhenBothMiss(t *testing.T) {
	t.Parallel()
	r := NewActionResolver(
		&fakeSRGetter{model: nil},
		&fakeDSLookuper{actions: nil, gotSDK: nil},
	)
	model := &ServiceModel{ARNNamespace: "ec2", Dir: "ec2", EndpointPrefix: "ec2"}
	got, src := r.Resolve(t.Context(), model, "DescribeIpamPoolAllocations")
	if src != SourceDerived {
		t.Errorf("src = %v, want SourceDerived", src)
	}
	if len(got) != 1 || got[0] != "ec2:DescribeIpamPoolAllocations" {
		t.Errorf("actions = %v, want [ec2:DescribeIpamPoolAllocations]", got)
	}
}

func TestActionResolver_noneWhenNoNamespace(t *testing.T) {
	t.Parallel()
	r := NewActionResolver(
		&fakeSRGetter{model: nil},
		&fakeDSLookuper{actions: nil, gotSDK: nil},
	)
	// Empty keys → no SR/DS calls → derive with empty namespace → nil/SourceNone.
	// Deterministically exercises dedupeNonEmpty's empty-skip branch.
	model := &ServiceModel{ARNNamespace: "", Dir: "", EndpointPrefix: ""}
	got, src := r.Resolve(t.Context(), model, "Op")
	if src != SourceNone || got != nil {
		t.Errorf("got %v,%v want nil,SourceNone", got, src)
	}
}

func TestActionResolver_failsClosedWhenServiceRefUnavailable(t *testing.T) {
	t.Parallel()
	// Service Reference errors, iam-dataset misses, and there is no ARN
	// namespace to derive from: the resolver must yield SourceNone (deny), not
	// authorize.
	r := NewActionResolver(
		erroringServiceRef{},
		&fakeDSLookuper{actions: nil, gotSDK: nil},
	)
	model := &ServiceModel{ARNNamespace: "", Dir: "svc", EndpointPrefix: "svc"}
	acts, src := r.Resolve(t.Context(), model, "SomeOp")
	if src != SourceNone {
		t.Fatalf("source = %v, want SourceNone (fail-closed)", src)
	}
	if len(acts) != 0 {
		t.Fatalf("actions = %v, want none", acts)
	}
}

// TestActionResolver_bug4_S3NamesResolveViaServiceRef pins the bug #4 fix: the
// real ServiceRefRegistry over the recorded fixture resolves the S3 name
// mismatches authoritatively. ListObjectsV2 deliberately over-lists
// s3:GetObjectAcl alongside s3:ListBucket — require-all keeps both (spec §9).
func TestActionResolver_bug4_S3NamesResolveViaServiceRef(t *testing.T) {
	t.Parallel()
	sr := NewServiceRefRegistry(ServiceRefRegistryConfig{
		Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		Fetcher: func(context.Context, string) ([]byte, error) { return readSRFixture(t), nil },
	})
	r := NewActionResolver(sr, &fakeDSLookuper{actions: nil, gotSDK: nil})
	cases := map[string][]string{
		"ListBuckets":   {"s3:ListAllMyBuckets"},
		"ListObjectsV2": {"s3:GetObjectAcl", "s3:ListBucket"},
	}
	model := &ServiceModel{ARNNamespace: "s3", Dir: "s3", EndpointPrefix: "s3"}
	for op, want := range cases {
		got, src := r.Resolve(t.Context(), model, op)
		if src != SourceServiceRef || !equalStrings(got, want) {
			t.Errorf("Resolve(%q) = %v,%v want %v,SourceServiceRef", op, got, src, want)
		}
	}
}

type fakeKeyedSR struct{ docs map[string]*ServiceRefModel }

func (f *fakeKeyedSR) Get(_ context.Context, key string) *ServiceRefModel {
	return f.docs[key]
}

func TestActionResolver_orderedKeyFallbackViaDir(t *testing.T) {
	t.Parallel()
	// CloudWatch: arnNamespace "monitoring" returns a doc that loads but lacks the
	// op (exercises the op-not-present continue), then dir "cloudwatch" hits.
	sr := &fakeKeyedSR{docs: map[string]*ServiceRefModel{
		"monitoring": {Service: "monitoring", Operations: map[string]SROperation{
			"SomeOtherOp": {
				AuthorizedActions: []string{"cloudwatch:SomeOtherOp"},
				SDKNames:          nil,
			},
		}},
		"cloudwatch": {Service: "cloudwatch", Operations: map[string]SROperation{
			"DescribeAlarms": {
				AuthorizedActions: []string{"cloudwatch:DescribeAlarms"},
				SDKNames:          nil,
			},
		}},
	}}
	r := NewActionResolver(sr, &fakeDSLookuper{actions: nil, gotSDK: nil})
	// arnNamespace==endpointPrefix=="monitoring" (dup, exercises dedupe), dir=="cloudwatch".
	m := &ServiceModel{ARNNamespace: "monitoring", Dir: "cloudwatch", EndpointPrefix: "monitoring"}
	got, src := r.Resolve(t.Context(), m, "DescribeAlarms")
	if src != SourceServiceRef || len(got) != 1 || got[0] != "cloudwatch:DescribeAlarms" {
		t.Errorf("Resolve = (%v,%v), want ([cloudwatch:DescribeAlarms], ServiceRef)", got, src)
	}
}

func s3ControlModel() *ServiceModel {
	return &ServiceModel{
		SDKID: "S3 Control", ARNNamespace: "s3", Dir: "s3-control",
		EndpointPrefix: "s3-control", NamespaceShadowed: true,
	}
}

func TestActionResolver_shadowedResolvesViaSDKID(t *testing.T) {
	t.Parallel()
	// Service Reference for the shared "s3" namespace WOULD return the bucket
	// action, but a shadowed model must never consult it: it has no s3-control
	// doc (own keys miss) and resolves via the SDK-id iam-dataset instead.
	sr := &fakeKeyedSR{docs: map[string]*ServiceRefModel{
		"s3": {Service: "s3", Operations: map[string]SROperation{
			"GetPublicAccessBlock": {
				AuthorizedActions: []string{"s3:GetBucketPublicAccessBlock"},
				SDKNames:          []string{"s3", "s3control"},
			},
		}},
	}}
	ds := &fakeDSLookuper{sdkActions: map[string][]string{
		"GetPublicAccessBlock": {"s3:GetAccountPublicAccessBlock"},
	}}
	r := NewActionResolver(sr, ds)
	got, src := r.Resolve(t.Context(), s3ControlModel(), "GetPublicAccessBlock")
	if src != SourceIAMDataset || len(got) != 1 || got[0] != "s3:GetAccountPublicAccessBlock" {
		t.Fatalf("Resolve = (%v,%v), want ([s3:GetAccountPublicAccessBlock], SourceIAMDataset)", got, src)
	}
	if ds.gotSDKID != "S3 Control" {
		t.Errorf("LookupSDKID got sdkID %q, want %q", ds.gotSDKID, "S3 Control")
	}
}

func TestActionResolver_shadowedServiceRefUnavailable(t *testing.T) {
	t.Parallel()
	// Service Reference entirely unavailable: the shadowed model still resolves
	// via the iam-dataset, never the bucket action (the outage regression path).
	ds := &fakeDSLookuper{sdkActions: map[string][]string{
		"GetPublicAccessBlock": {"s3:GetAccountPublicAccessBlock"},
	}}
	r := NewActionResolver(erroringServiceRef{}, ds)
	got, src := r.Resolve(t.Context(), s3ControlModel(), "GetPublicAccessBlock")
	if src != SourceIAMDataset || len(got) != 1 || got[0] != "s3:GetAccountPublicAccessBlock" {
		t.Fatalf("Resolve = (%v,%v), want ([s3:GetAccountPublicAccessBlock], SourceIAMDataset)", got, src)
	}
}

func TestActionResolver_shadowedFailsClosedOnDatasetMiss(t *testing.T) {
	t.Parallel()
	// Shadowed model, own-key Service Reference miss, iam-dataset miss: deny.
	r := NewActionResolver(erroringServiceRef{}, &fakeDSLookuper{sdkActions: nil})
	got, src := r.Resolve(t.Context(), s3ControlModel(), "GetPublicAccessBlock")
	if src != SourceNone || len(got) != 0 {
		t.Fatalf("Resolve = (%v,%v), want (nil, SourceNone)", got, src)
	}
}

func TestActionResolver_shadowedOwnKeyServiceRefHit(t *testing.T) {
	t.Parallel()
	// If a shadowed model's OWN-key Service Reference doc exists, it is used.
	sr := &fakeKeyedSR{docs: map[string]*ServiceRefModel{
		"s3-control": {Service: "s3-control", Operations: map[string]SROperation{
			"GetPublicAccessBlock": {AuthorizedActions: []string{"s3:GetAccountPublicAccessBlock"}, SDKNames: nil},
		}},
	}}
	r := NewActionResolver(sr, &fakeDSLookuper{})
	got, src := r.Resolve(t.Context(), s3ControlModel(), "GetPublicAccessBlock")
	if src != SourceServiceRef || len(got) != 1 || got[0] != "s3:GetAccountPublicAccessBlock" {
		t.Fatalf("Resolve = (%v,%v), want ([s3:GetAccountPublicAccessBlock], SourceServiceRef)", got, src)
	}
}

func TestActionResolver_shadowedOwnKeyDocMissingOpFallsThrough(t *testing.T) {
	t.Parallel()
	// Own-key Service Reference doc EXISTS but lacks the op: resolveShadowed must
	// fall through to LookupSDKID (covers the own-key success-but-op-absent path).
	sr := &fakeKeyedSR{docs: map[string]*ServiceRefModel{
		"s3-control": {Service: "s3-control", Operations: map[string]SROperation{}},
	}}
	ds := &fakeDSLookuper{sdkActions: map[string][]string{
		"GetPublicAccessBlock": {"s3:GetAccountPublicAccessBlock"},
	}}
	r := NewActionResolver(sr, ds)
	got, src := r.Resolve(t.Context(), s3ControlModel(), "GetPublicAccessBlock")
	if src != SourceIAMDataset || len(got) != 1 || got[0] != "s3:GetAccountPublicAccessBlock" {
		t.Fatalf("Resolve = (%v,%v), want ([s3:GetAccountPublicAccessBlock], SourceIAMDataset)", got, src)
	}
}

func TestActionResolver_notShadowedUnchanged(t *testing.T) {
	t.Parallel()
	// A non-shadowed S3 model resolves GetPublicAccessBlock to the bucket action
	// via Service Reference exactly as before.
	sr := &fakeKeyedSR{docs: map[string]*ServiceRefModel{
		"s3": {Service: "s3", Operations: map[string]SROperation{
			"GetPublicAccessBlock": {AuthorizedActions: []string{"s3:GetBucketPublicAccessBlock"}, SDKNames: nil},
		}},
	}}
	r := NewActionResolver(sr, &fakeDSLookuper{})
	model := &ServiceModel{SDKID: "S3", ARNNamespace: "s3", Dir: "s3", EndpointPrefix: "s3"} // NamespaceShadowed false.
	got, src := r.Resolve(t.Context(), model, "GetPublicAccessBlock")
	if src != SourceServiceRef || len(got) != 1 || got[0] != "s3:GetBucketPublicAccessBlock" {
		t.Fatalf("Resolve = (%v,%v), want ([s3:GetBucketPublicAccessBlock], SourceServiceRef)", got, src)
	}
}
