package aws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// awsToolCall projects a whole http_request tool call down to the aws_auth
// block, exactly as auth's dispatcher does before it calls a gate.
func awsToolCall(toolCall string) authreq.ProviderArgs {
	return authreq.NewProviderArgs(json.RawMessage(toolCall), "aws")
}

func TestProvider_AuthorizeAction_happyPath(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{
		allowed:              map[string]bool{"s3:ListBuckets": true},
		smithyEndpointPrefix: "",
	})
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), v, raw); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}
}

func TestProvider_AuthorizeAction_permissionlessAllowed(t *testing.T) {
	t.Parallel()
	// A permissionless op resolves to SourcePermissionless with no action; the
	// provider must allow it without requiring policy authorization. The
	// deny-all evaluator (empty allow-map) proves no action was checked.
	p := &Provider{
		models:    &fakeArchive{models: []*ServiceModel{s3MinModel(t)}, err: nil},
		resolver:  &fakeResolver{actions: nil, source: SourcePermissionless},
		evaluator: &fakeEvaluator{allowed: map[string]bool{}, err: nil},
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), v, raw); err != nil {
		t.Fatalf("AuthorizeAction (permissionless must allow): %v", err)
	}
}

func TestProvider_AuthorizeAction_deniedAction(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: map[string]bool{}, smithyEndpointPrefix: ""})
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), v, raw)
	if !errors.Is(err, ErrPolicyDenied) {
		t.Errorf("err = %v, want ErrPolicyDenied", err)
	}
}

// TestProvider_AuthorizeAction_endpointPrefixMismatchSkips covers the defensive
// guard: a returned candidate whose EndpointPrefix != parsed prefix is skipped.
// As the only candidate, no candidate serves the request → ErrActionUnresolved.
func TestProvider_AuthorizeAction_endpointPrefixMismatchSkips(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{
		allowed:              map[string]bool{"s3:ListBuckets": true},
		smithyEndpointPrefix: "NOT-s3",
	})
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), v, raw)
	if !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("err = %v, want ErrActionUnresolved (mismatched candidate skipped)", err)
	}
}

func TestProvider_AuthorizeAction_malformedJSON(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: nil, smithyEndpointPrefix: ""})
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	err := p.AuthorizeAction(t.Context(), v, awsToolCall(`{bad`))
	if err == nil {
		t.Errorf("expected JSON parse error")
	}
}

func TestProvider_AuthorizeAction_missingAWSAuth(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: nil, smithyEndpointPrefix: ""})
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	err := p.AuthorizeAction(t.Context(), v, awsToolCall(`{}`))
	if err == nil {
		t.Errorf("expected missing aws_auth error")
	}
}

func TestProvider_AuthorizeAction_unrecognizedHost(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: nil, smithyEndpointPrefix: ""})
	v := mustProviderView(t, http.MethodGet, "https://attacker.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), v, raw)
	if !errors.Is(err, ErrHostPattern) {
		t.Errorf("err = %v, want ErrHostPattern", err)
	}
}

func TestProvider_AuthorizeAction_modelResolveFails(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: nil, err: errors.New("archive unavailable")},
		resolver:  &fakeResolver{actions: []string{"s3:ListBuckets"}, source: SourceServiceRef},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), v, raw)
	if err == nil {
		t.Errorf("expected archive error")
	}
}

// TestProvider_AuthorizeAction_classifierUnknownOpSkips covers a candidate that
// does not serve the operation (ErrClassifierUnknownOp): POST is not in the
// minimal S3 model so the single candidate is skipped → matched==0 →
// ErrActionUnresolved.
func TestProvider_AuthorizeAction_classifierUnknownOpSkips(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: []*ServiceModel{s3MinModel(t)}, err: nil},
		resolver:  &fakeResolver{actions: []string{"s3:ListBuckets"}, source: SourceServiceRef},
		evaluator: &fakeEvaluator{allowed: map[string]bool{"s3:ListBuckets": true}, err: nil},
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	v := mustProviderView(t, http.MethodPost, "https://s3.us-east-1.amazonaws.com/foo")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), v, raw)
	if !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("err = %v, want ErrActionUnresolved (unknown-op candidate skipped)", err)
	}
}

func TestProvider_AuthorizeAction_evaluatorFails(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: []*ServiceModel{s3MinModel(t)}, err: nil},
		resolver:  &fakeResolver{actions: []string{"s3:ListBuckets"}, source: SourceServiceRef},
		evaluator: &fakeEvaluator{allowed: nil, err: errors.New("throttled")},
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), v, raw)
	if err == nil {
		t.Errorf("expected evaluator error")
	}
}

func TestProvider_AuthorizeAction_unresolvedDenies(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: []*ServiceModel{s3MinModel(t)}, err: nil},
		resolver:  &fakeResolver{actions: nil, source: SourceNone},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), v, raw); !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("err = %v, want ErrActionUnresolved", err)
	}
}

// TestProvider_AuthorizeAction_collisionUnion covers a prefix collision: two
// candidates both match the operation, so the conservative UNION of their action
// sets is passed to the evaluator.
func TestProvider_AuthorizeAction_collisionUnion(t *testing.T) {
	t.Parallel()
	a := s3MinModel(t)
	a.Dir = "ses"
	a.EndpointPrefix = "email"
	b := s3MinModel(t)
	b.Dir = "sesv2"
	b.EndpointPrefix = "email"
	ev := &capturingEvaluator{allow: true}
	p := &Provider{
		models: &fakeArchive{models: []*ServiceModel{a, b}, err: nil},
		resolver: &keyedResolver{byDir: map[string]resolverResult{
			"ses":   {actions: []string{"ses:ListBuckets"}, source: SourceServiceRef},
			"sesv2": {actions: []string{"sesv2:ListBuckets"}, source: SourceServiceRef},
		}},
		evaluator: ev,
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	v := mustProviderView(t, http.MethodGet, "https://email.us-east-1.amazonaws.com/")
	raw := awsToolCall(`{"aws_auth":{"service":"email","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), v, raw); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}
	want := []string{"ses:ListBuckets", "sesv2:ListBuckets"}
	if !slices.Equal(ev.got, want) {
		t.Errorf("evaluator received %v, want union %v", ev.got, want)
	}
}

func TestProvider_AuthorizeAction_virtualHostedClassifiesObjectOps(t *testing.T) {
	t.Parallel()
	// End-to-end regression: a virtual-hosted (or access-point) request carries
	// the bucket in the host, so AuthorizeAction must classify object ops correctly
	// and gate the RIGHT IAM action — s3:GetObject for an object GET (not
	// s3:ListBucket), and s3:ListBucket for a bucket-root GET (not s3:ListAllMyBuckets).
	model := &ServiceModel{
		Dir: "s3", ARNNamespace: "s3", EndpointPrefix: "s3", SigningName: "s3",
		Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetObject":   {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}"},
			"ListObjects": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"ListBuckets": {HTTPMethod: "GET", URITemplate: "/"},
		},
	}
	cases := []struct {
		name, url string
		want      []string
	}{
		{
			"vhost object GET",
			"https://my-bucket.s3.us-east-1.amazonaws.com/key.txt",
			[]string{"s3:GetObject"},
		},
		{
			"vhost bucket root GET",
			"https://my-bucket.s3.us-east-1.amazonaws.com/",
			[]string{"s3:ListBucket"},
		},
		{
			"access-point object GET",
			"https://myendpoint-111122223333.s3-accesspoint.us-east-1.amazonaws.com/key.txt",
			[]string{"s3:GetObject"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ev := &capturingEvaluator{allow: true}
			p := &Provider{
				models: &fakeArchive{models: []*ServiceModel{model}, err: nil},
				resolver: &opKeyedResolver{byOp: map[string]resolverResult{
					"GetObject":   {actions: []string{"s3:GetObject"}, source: SourceServiceRef},
					"ListObjects": {actions: []string{"s3:ListBucket"}, source: SourceServiceRef},
					"ListBuckets": {actions: []string{"s3:ListAllMyBuckets"}, source: SourceServiceRef},
				}},
				evaluator: ev,
				policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
			}
			v := mustProviderView(t, http.MethodGet, c.url)
			raw := awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
			if err := p.AuthorizeAction(t.Context(), v, raw); err != nil {
				t.Fatalf("AuthorizeAction: %v", err)
			}
			if !slices.Equal(ev.got, c.want) {
				t.Errorf("evaluator received %v, want %v", ev.got, c.want)
			}
		})
	}
}

// tieModel returns a REST model whose two named operations both match
// POST /resource with no discriminator, so classification ties between them.
func tieModel(dir string, ops ...string) *ServiceModel {
	m := &ServiceModel{
		Dir: dir, ARNNamespace: dir, EndpointPrefix: "example", SigningName: "example",
		Protocol:   ProtocolRestJSON1,
		Operations: map[string]Operation{},
	}
	for _, op := range ops {
		m.Operations[op] = Operation{HTTPMethod: "POST", URITemplate: "/resource"}
	}
	return m
}

// tieProvider wires a tied model with a per-operation resolver and an
// evaluator that allows exactly the given actions.
func tieProvider(models []*ServiceModel, resolver Resolver, allowed ...string) (*Provider, *capturingEvaluator) {
	ev := &capturingEvaluator{allow: true, allowed: map[string]bool{}}
	for _, a := range allowed {
		ev.allowed[a] = true
	}
	p := &Provider{
		models:    &fakeArchive{models: models, err: nil},
		resolver:  resolver,
		evaluator: ev,
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	return p, ev
}

func tieCall(t *testing.T, p *Provider) error {
	t.Helper()
	v := mustProviderView(t, http.MethodPost, "https://example.us-east-1.amazonaws.com/resource")
	return p.AuthorizeAction(t.Context(), v, awsToolCall(`{"aws_auth":{"service":"example","region":"us-east-1"}}`))
}

// TestProvider_AuthorizeAction_tieRequiresEveryCandidate is the issue #309
// fixture: two operations tie for POST /resource and resolve to distinct
// actions. A policy permitting only one of them must deny whichever name sorts
// first, and only a policy permitting both allows.
func TestProvider_AuthorizeAction_tieRequiresEveryCandidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		read    string // operation name resolving to example:Read
		write   string // operation name resolving to example:Write
		allowed []string
		wantErr error
		wantGot []string
	}{
		{"read sorts first, only read allowed", "ARead", "ZWrite", []string{"example:Read"}, ErrPolicyDenied, nil},
		{"write sorts first, only read allowed", "ZRead", "AWrite", []string{"example:Read"}, ErrPolicyDenied, nil},
		{"only write allowed", "ARead", "ZWrite", []string{"example:Write"}, ErrPolicyDenied, nil},
		{
			"both allowed", "ARead", "ZWrite",
			[]string{"example:Read", "example:Write"},
			nil,
			[]string{"example:Read", "example:Write"},
		},
		{
			"both allowed, write sorts first", "ZRead", "AWrite",
			[]string{"example:Read", "example:Write"},
			nil,
			[]string{"example:Write", "example:Read"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			resolver := &opKeyedResolver{byOp: map[string]resolverResult{
				c.read:  {actions: []string{"example:Read"}, source: SourceServiceRef},
				c.write: {actions: []string{"example:Write"}, source: SourceServiceRef},
			}}
			p, ev := tieProvider([]*ServiceModel{tieModel("example", c.read, c.write)}, resolver, c.allowed...)
			err := tieCall(t, p)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			if c.wantErr == nil && !slices.Equal(ev.got, c.wantGot) {
				t.Errorf("evaluator received %v, want %v", ev.got, c.wantGot)
			}
		})
	}
}

// TestProvider_AuthorizeAction_threeWayTie: every single-action policy denies
// and only the complete union allows.
func TestProvider_AuthorizeAction_threeWayTie(t *testing.T) {
	t.Parallel()
	resolver := &opKeyedResolver{byOp: map[string]resolverResult{
		"A": {actions: []string{"example:A"}, source: SourceServiceRef},
		"B": {actions: []string{"example:B"}, source: SourceServiceRef},
		"C": {actions: []string{"example:C"}, source: SourceServiceRef},
	}}
	for _, only := range []string{"example:A", "example:B", "example:C"} {
		t.Run("only "+only, func(t *testing.T) {
			t.Parallel()
			p, _ := tieProvider([]*ServiceModel{tieModel("example", "C", "A", "B")}, resolver, only)
			if err := tieCall(t, p); !errors.Is(err, ErrPolicyDenied) {
				t.Errorf("err = %v, want ErrPolicyDenied", err)
			}
		})
	}
	t.Run("all three", func(t *testing.T) {
		t.Parallel()
		p, ev := tieProvider([]*ServiceModel{tieModel("example", "C", "A", "B")}, resolver,
			"example:A", "example:B", "example:C")
		if err := tieCall(t, p); err != nil {
			t.Fatalf("AuthorizeAction: %v", err)
		}
		if want := []string{"example:A", "example:B", "example:C"}; !slices.Equal(ev.got, want) {
			t.Errorf("evaluator received %v, want %v", ev.got, want)
		}
	})
}

// TestProvider_AuthorizeAction_tieUnresolvedCandidateDenies: a tied candidate
// that resolves to nothing denies before any policy evaluation, even though its
// sibling is allowed. Each half of the fail-closed predicate is pinned on its
// own: no source, a source with no actions, and actions with no source.
func TestProvider_AuthorizeAction_tieUnresolvedCandidateDenies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		sibling resolverResult
	}{
		{"no source and no actions", resolverResult{actions: nil, source: SourceNone}},
		{"source without actions", resolverResult{actions: nil, source: SourceServiceRef}},
		{"actions without source", resolverResult{actions: []string{"example:Write"}, source: SourceNone}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			resolver := &opKeyedResolver{byOp: map[string]resolverResult{
				"ARead":  {actions: []string{"example:Read"}, source: SourceServiceRef},
				"ZWrite": c.sibling,
			}}
			p, ev := tieProvider([]*ServiceModel{tieModel("example", "ARead", "ZWrite")}, resolver,
				"example:Read", "example:Write")
			if err := tieCall(t, p); !errors.Is(err, ErrActionUnresolved) {
				t.Fatalf("err = %v, want ErrActionUnresolved", err)
			}
			if ev.got != nil {
				t.Errorf("evaluator was called with %v; an unresolved candidate must deny first", ev.got)
			}
		})
	}
}

// TestProvider_AuthorizeAction_tiePermissionlessCandidate: a permissionless
// candidate contributes no action but does not excuse its tied sibling.
func TestProvider_AuthorizeAction_tiePermissionlessCandidate(t *testing.T) {
	t.Parallel()
	resolver := &opKeyedResolver{byOp: map[string]resolverResult{
		"AFree":  {actions: nil, source: SourcePermissionless},
		"ZWrite": {actions: []string{"example:Write"}, source: SourceServiceRef},
	}}
	t.Run("sibling denied", func(t *testing.T) {
		t.Parallel()
		p, _ := tieProvider([]*ServiceModel{tieModel("example", "AFree", "ZWrite")}, resolver)
		if err := tieCall(t, p); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("err = %v, want ErrPolicyDenied", err)
		}
	})
	t.Run("sibling allowed", func(t *testing.T) {
		t.Parallel()
		p, ev := tieProvider([]*ServiceModel{tieModel("example", "AFree", "ZWrite")}, resolver, "example:Write")
		if err := tieCall(t, p); err != nil {
			t.Fatalf("AuthorizeAction: %v", err)
		}
		if want := []string{"example:Write"}; !slices.Equal(ev.got, want) {
			t.Errorf("evaluator received %v, want %v", ev.got, want)
		}
	})
}

// TestProvider_AuthorizeAction_tieDedupesSharedActions: tied candidates that
// share an action put it in the required set once, while each candidate's own
// actions still all arrive, so the evaluator and the denial message name every
// action a single time.
func TestProvider_AuthorizeAction_tieDedupesSharedActions(t *testing.T) {
	t.Parallel()
	resolver := &opKeyedResolver{byOp: map[string]resolverResult{
		"ListThings":   {actions: []string{"example:Shared", "example:Read"}, source: SourceServiceRef},
		"ListThingsV2": {actions: []string{"example:Shared", "example:Write"}, source: SourceServiceRef},
	}}
	p, ev := tieProvider([]*ServiceModel{tieModel("example", "ListThings", "ListThingsV2")}, resolver,
		"example:Shared", "example:Read", "example:Write")
	if err := tieCall(t, p); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}
	if want := []string{"example:Shared", "example:Read", "example:Write"}; !slices.Equal(ev.got, want) {
		t.Errorf("evaluator received %v, want %v", ev.got, want)
	}
}

// TestProvider_AuthorizeAction_s3RootUnion pins the canonical S3 bucket listing
// on the fixture's real shape: GET / ties ListBuckets with ListDirectoryBuckets,
// so the gate requires s3:ListAllMyBuckets and s3express:ListAllMyDirectoryBuckets
// together (both granted by SecurityAudit) and denies a policy holding only one.
func TestProvider_AuthorizeAction_s3RootUnion(t *testing.T) {
	t.Parallel()
	resolver := &opKeyedResolver{byOp: map[string]resolverResult{
		"ListBuckets":          {actions: []string{"s3:ListAllMyBuckets"}, source: SourceServiceRef},
		"ListDirectoryBuckets": {actions: []string{"s3express:ListAllMyDirectoryBuckets"}, source: SourceIAMDataset},
	}}
	call := func(t *testing.T, p *Provider) error {
		t.Helper()
		v := mustProviderView(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
		return p.AuthorizeAction(t.Context(), v, awsToolCall(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`))
	}
	t.Run("both granted", func(t *testing.T) {
		t.Parallel()
		p, ev := tieProvider([]*ServiceModel{s3MinModel(t)}, resolver,
			"s3:ListAllMyBuckets", "s3express:ListAllMyDirectoryBuckets")
		if err := call(t, p); err != nil {
			t.Fatalf("AuthorizeAction: %v", err)
		}
		want := []string{"s3:ListAllMyBuckets", "s3express:ListAllMyDirectoryBuckets"}
		if !slices.Equal(ev.got, want) {
			t.Errorf("evaluator received %v, want %v", ev.got, want)
		}
	})
	t.Run("only ListAllMyBuckets granted", func(t *testing.T) {
		t.Parallel()
		p, _ := tieProvider([]*ServiceModel{s3MinModel(t)}, resolver, "s3:ListAllMyBuckets")
		if err := call(t, p); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("err = %v, want ErrPolicyDenied", err)
		}
	})
}

// TestProvider_AuthorizeAction_mrapReadsUnderDefaultPolicy pins the S3 Control
// multi-region access point reads under the default policy, which grants the
// plain get and its policy reads but not the routes read. Each sub-resource
// read outranks the plain get it extends, so the gate requires that read's
// action alone: the policy read is allowed on its own action, and the routes
// read is denied naming only the operation AWS runs for it.
func TestProvider_AuthorizeAction_mrapReadsUnderDefaultPolicy(t *testing.T) {
	t.Parallel()
	resolver := &opKeyedResolver{byOp: map[string]resolverResult{
		"GetMultiRegionAccessPoint": {
			actions: []string{"s3:GetMultiRegionAccessPoint"},
			source:  SourceIAMDataset,
		},
		"GetMultiRegionAccessPointPolicy": {
			actions: []string{"s3:GetMultiRegionAccessPointPolicy"},
			source:  SourceIAMDataset,
		},
		"GetMultiRegionAccessPointPolicyStatus": {
			actions: []string{"s3:GetMultiRegionAccessPointPolicyStatus"},
			source:  SourceIAMDataset,
		},
		"GetMultiRegionAccessPointRoutes": {
			actions: []string{"s3:GetMultiRegionAccessPointRoutes"},
			source:  SourceIAMDataset,
		},
	}}
	granted := []string{
		"s3:GetMultiRegionAccessPoint",
		"s3:GetMultiRegionAccessPointPolicy",
		"s3:GetMultiRegionAccessPointPolicyStatus",
	}
	cases := []struct {
		path    string
		wantErr error
		wantGot []string
	}{
		{"/v20180820/mrap/instances/my-mrap", nil, []string{"s3:GetMultiRegionAccessPoint"}},
		{"/v20180820/mrap/instances/my-mrap/policy", nil, []string{"s3:GetMultiRegionAccessPointPolicy"}},
		{"/v20180820/mrap/instances/my-mrap/routes", ErrPolicyDenied, []string{"s3:GetMultiRegionAccessPointRoutes"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			t.Parallel()
			p, ev := tieProvider([]*ServiceModel{mrapModel()}, resolver, granted...)
			v := mustProviderView(t, http.MethodGet, "https://123456789012.s3-control.us-east-1.amazonaws.com"+c.path)
			v.Header.Set("X-Amz-Account-Id", "123456789012")
			err := p.AuthorizeAction(
				t.Context(),
				v,
				awsToolCall(`{"aws_auth":{"service":"s3-control","region":"us-east-1"}}`),
			)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			if !slices.Equal(ev.got, c.wantGot) {
				t.Errorf("evaluator received %v, want %v", ev.got, c.wantGot)
			}
		})
	}
}

// dirOpResolver keys results by "<model dir>/<op>" so a collision test can tie
// operations inside one model while another model on the same prefix resolves
// its own.
type dirOpResolver struct {
	by map[string]resolverResult
}

func (r *dirOpResolver) Resolve(_ context.Context, model *ServiceModel, op string) ([]string, ActionSource) {
	res := r.by[model.Dir+"/"+op]
	return res.actions, res.source
}

// TestProvider_AuthorizeAction_tieNotMaskedByCollidingModel: a tie inside one
// model still contributes every candidate when another model shares the
// endpoint prefix; the colliding model's own action cannot stand in for the
// tied sibling.
func TestProvider_AuthorizeAction_tieNotMaskedByCollidingModel(t *testing.T) {
	t.Parallel()
	models := func() []*ServiceModel {
		return []*ServiceModel{tieModel("example", "ARead", "ZWrite"), tieModel("example2", "Only")}
	}
	resolver := &dirOpResolver{by: map[string]resolverResult{
		"example/ARead":  {actions: []string{"example:Read"}, source: SourceServiceRef},
		"example/ZWrite": {actions: []string{"example:Write"}, source: SourceServiceRef},
		"example2/Only":  {actions: []string{"example2:Only"}, source: SourceServiceRef},
	}}
	t.Run("tied sibling missing from policy", func(t *testing.T) {
		t.Parallel()
		p, _ := tieProvider(models(), resolver, "example:Read", "example2:Only")
		if err := tieCall(t, p); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("err = %v, want ErrPolicyDenied", err)
		}
	})
	t.Run("full union", func(t *testing.T) {
		t.Parallel()
		p, ev := tieProvider(models(), resolver, "example:Read", "example:Write", "example2:Only")
		if err := tieCall(t, p); err != nil {
			t.Fatalf("AuthorizeAction: %v", err)
		}
		if want := []string{"example:Read", "example:Write", "example2:Only"}; !slices.Equal(ev.got, want) {
			t.Errorf("evaluator received %v, want %v", ev.got, want)
		}
	})
}

func TestNewProvider_constructs(t *testing.T) {
	t.Parallel()
	p := NewProvider(
		&fakeArchive{models: nil, err: nil},
		&fakeResolver{actions: nil, source: SourceNone},
		&fakeEvaluator{allowed: nil, err: nil},
		"arn",
	)
	if p == nil || p.policyARN != "arn" {
		t.Errorf("NewProvider returned %+v", p)
	}
}

func TestProvider_ResolveSigningName_success(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: []*ServiceModel{{EndpointPrefix: "api.ecr", SigningName: "ecr"}}, err: nil},
		resolver:  &fakeResolver{actions: nil, source: SourceNone},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn",
	}
	got, err := p.ResolveSigningName(t.Context(), "api.ecr.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatalf("ResolveSigningName: %v", err)
	}
	if got != "ecr" {
		t.Errorf("ResolveSigningName = %q, want ecr", got)
	}
}

// TestProvider_ResolveSigningName_s3AccessPoint proves the signing half of the
// access-point fix: a virtual-hosted access-point host parses to service "s3"
// and resolves the "s3" SigV4 signing name (no s3-accesspoint signing variance).
func TestProvider_ResolveSigningName_s3AccessPoint(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: []*ServiceModel{{EndpointPrefix: "s3", SigningName: "s3"}}, err: nil},
		resolver:  &fakeResolver{actions: nil, source: SourceNone},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn",
	}
	got, err := p.ResolveSigningName(t.Context(), "myendpoint-111122223333.s3-accesspoint.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatalf("ResolveSigningName: %v", err)
	}
	if got != "s3" {
		t.Errorf("ResolveSigningName = %q, want s3", got)
	}
}

func TestProvider_ResolveSigningName_parseHostFails(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: nil, err: nil},
		resolver:  &fakeResolver{actions: nil, source: SourceNone},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn",
	}
	if _, err := p.ResolveSigningName(t.Context(), "attacker.com"); !errors.Is(err, ErrHostPattern) {
		t.Errorf("err = %v, want ErrHostPattern", err)
	}
}

func TestProvider_ResolveSigningName_modelResolveFails(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: nil, err: errors.New("archive unavailable")},
		resolver:  &fakeResolver{actions: nil, source: SourceNone},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn",
	}
	if _, err := p.ResolveSigningName(t.Context(), "api.ecr.us-east-1.amazonaws.com"); err == nil {
		t.Error("expected archive error")
	}
}

// TestProvider_ResolveSigningName_noCandidate covers both the defensive
// endpoint-prefix-mismatch skip and the empty-result fail: the only model
// answers on a different prefix, so no signing name resolves.
func TestProvider_ResolveSigningName_noCandidate(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models:    &fakeArchive{models: []*ServiceModel{{EndpointPrefix: "OTHER", SigningName: "x"}}, err: nil},
		resolver:  &fakeResolver{actions: nil, source: SourceNone},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn",
	}
	if _, err := p.ResolveSigningName(
		t.Context(),
		"api.ecr.us-east-1.amazonaws.com",
	); !errors.Is(
		err,
		ErrSigningNameUnresolved,
	) {
		t.Errorf("err = %v, want ErrSigningNameUnresolved", err)
	}
}

// TestProvider_ResolveSigningName_ambiguous covers a prefix collision whose
// candidates disagree on the signing name — fail closed rather than guess.
func TestProvider_ResolveSigningName_ambiguous(t *testing.T) {
	t.Parallel()
	p := &Provider{
		models: &fakeArchive{models: []*ServiceModel{
			{EndpointPrefix: "api.ecr", SigningName: "ecr"},
			{EndpointPrefix: "api.ecr", SigningName: "ecr-other"},
		}, err: nil},
		resolver:  &fakeResolver{actions: nil, source: SourceNone},
		evaluator: &fakeEvaluator{allowed: nil, err: nil},
		policyARN: "arn",
	}
	if _, err := p.ResolveSigningName(
		t.Context(),
		"api.ecr.us-east-1.amazonaws.com",
	); !errors.Is(
		err,
		ErrSigningNameUnresolved,
	) {
		t.Errorf("err = %v, want ErrSigningNameUnresolved", err)
	}
}

type providerTestSetup struct {
	allowed              map[string]bool
	smithyEndpointPrefix string
}

func newTestProvider(t *testing.T, setup providerTestSetup) *Provider {
	t.Helper()
	model := s3MinModel(t)
	if setup.smithyEndpointPrefix != "" {
		model.EndpointPrefix = setup.smithyEndpointPrefix
	}
	return &Provider{
		models:    &fakeArchive{models: []*ServiceModel{model}, err: nil},
		resolver:  &fakeResolver{actions: []string{"s3:ListBuckets"}, source: SourceServiceRef},
		evaluator: &fakeEvaluator{allowed: setup.allowed, err: nil},
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
}

type fakeArchive struct {
	models []*ServiceModel
	err    error
}

func (a *fakeArchive) Resolve(context.Context, string) ([]*ServiceModel, error) {
	return a.models, a.err
}

type fakeResolver struct {
	actions []string
	source  ActionSource
}

func (r *fakeResolver) Resolve(_ context.Context, _ *ServiceModel, _ string) ([]string, ActionSource) {
	return r.actions, r.source
}

type resolverResult struct {
	actions []string
	source  ActionSource
}

// keyedResolver returns a per-model result keyed by ServiceModel.Dir, so a
// collision test can assert each candidate contributes its own actions.
type keyedResolver struct {
	byDir map[string]resolverResult
}

func (r *keyedResolver) Resolve(_ context.Context, model *ServiceModel, _ string) ([]string, ActionSource) {
	res := r.byDir[model.Dir]
	return res.actions, res.source
}

// opKeyedResolver returns a per-operation result keyed by the classified op name,
// so an end-to-end test can assert the evaluator receives the action(s) of the
// correctly-classified operation.
type opKeyedResolver struct {
	byOp map[string]resolverResult
}

func (r *opKeyedResolver) Resolve(_ context.Context, _ *ServiceModel, op string) ([]string, ActionSource) {
	res := r.byOp[op]
	return res.actions, res.source
}

type fakeEvaluator struct {
	allowed map[string]bool
	err     error
}

func (e *fakeEvaluator) AllowedAll(_ context.Context, actions []string) (bool, error) {
	if e.err != nil {
		return false, e.err
	}
	for _, a := range actions {
		if !e.allowed[a] {
			return false, nil
		}
	}
	return true, nil
}

// capturingEvaluator records the action set it received. With a nil allowed
// map it answers allow; otherwise every action must be in the map.
type capturingEvaluator struct {
	allow   bool
	allowed map[string]bool
	got     []string
}

func (e *capturingEvaluator) AllowedAll(_ context.Context, actions []string) (bool, error) {
	e.got = actions
	if e.allowed == nil {
		return e.allow, nil
	}
	for _, a := range actions {
		if !e.allowed[a] {
			return false, nil
		}
	}
	return true, nil
}

func mustProviderView(t *testing.T, method, raw string) authreq.View {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, raw, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return authreq.NewView(req, "")
}

// TestProvider_AuthorizeAction_encodedSlashRequiresBothReadings pins the case
// at the layer that decides: a policy granting only the operation the decoded
// reading names must not let the request through, because the service may run
// the one the wire reading names.
func TestProvider_AuthorizeAction_encodedSlashRequiresBothReadings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		allowed []string
		wantErr error
	}{
		{"only the decoded reading's action allowed", []string{"example:Policy"}, ErrPolicyDenied},
		{"only the wire reading's action allowed", []string{"example:Function"}, ErrPolicyDenied},
		{"both allowed", []string{"example:Function", "example:Policy"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			model := &ServiceModel{
				Dir: "example", ARNNamespace: "example", EndpointPrefix: "example",
				SigningName: "example", Protocol: ProtocolRestJSON1,
				Operations: map[string]Operation{
					"GetFunction": {HTTPMethod: "GET", URITemplate: "/2015-03-31/functions/{FunctionName}"},
					"GetPolicy":   {HTTPMethod: "GET", URITemplate: "/2015-03-31/functions/{FunctionName}/policy"},
				},
			}
			resolver := &opKeyedResolver{byOp: map[string]resolverResult{
				"GetFunction": {actions: []string{"example:Function"}, source: SourceServiceRef},
				"GetPolicy":   {actions: []string{"example:Policy"}, source: SourceServiceRef},
			}}
			p, _ := tieProvider([]*ServiceModel{model}, resolver, c.allowed...)
			v := mustProviderView(t, http.MethodGet,
				"https://example.us-east-1.amazonaws.com/2015-03-31/functions/my%2Fpolicy")
			err := p.AuthorizeAction(
				t.Context(),
				v,
				awsToolCall(`{"aws_auth":{"service":"example","region":"us-east-1"}}`),
			)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
		})
	}
}
