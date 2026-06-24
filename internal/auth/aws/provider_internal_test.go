package aws

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
)

func TestProvider_AuthorizeAction_happyPath(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{
		allowed:              map[string]bool{"s3:ListBuckets": true},
		smithyEndpointPrefix: "",
	})
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), req, raw); err != nil {
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
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), req, raw); err != nil {
		t.Fatalf("AuthorizeAction (permissionless must allow): %v", err)
	}
}

func TestProvider_AuthorizeAction_deniedAction(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: map[string]bool{}, smithyEndpointPrefix: ""})
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), req, raw)
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
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), req, raw)
	if !errors.Is(err, ErrActionUnresolved) {
		t.Errorf("err = %v, want ErrActionUnresolved (mismatched candidate skipped)", err)
	}
}

func TestProvider_AuthorizeAction_malformedJSON(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: nil, smithyEndpointPrefix: ""})
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	err := p.AuthorizeAction(t.Context(), req, []byte(`{bad`))
	if err == nil {
		t.Errorf("expected JSON parse error")
	}
}

func TestProvider_AuthorizeAction_missingAWSAuth(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: nil, smithyEndpointPrefix: ""})
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	err := p.AuthorizeAction(t.Context(), req, []byte(`{}`))
	if err == nil {
		t.Errorf("expected missing aws_auth error")
	}
}

func TestProvider_AuthorizeAction_unrecognizedHost(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t, providerTestSetup{allowed: nil, smithyEndpointPrefix: ""})
	req := mustProviderReq(t, http.MethodGet, "https://attacker.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), req, raw)
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
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), req, raw)
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
	req := mustProviderReq(t, http.MethodPost, "https://s3.us-east-1.amazonaws.com/foo")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), req, raw)
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
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	err := p.AuthorizeAction(t.Context(), req, raw)
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
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), req, raw); !errors.Is(err, ErrActionUnresolved) {
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
	req := mustProviderReq(t, http.MethodGet, "https://email.us-east-1.amazonaws.com/")
	raw := []byte(`{"aws_auth":{"service":"email","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), req, raw); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}
	want := []string{"ses:ListBuckets", "sesv2:ListBuckets"}
	if !slices.Equal(ev.got, want) {
		t.Errorf("evaluator received %v, want union %v", ev.got, want)
	}
}

func TestProvider_AuthorizeAction_virtualHostedClassifiesObjectOps(t *testing.T) {
	t.Parallel()
	// End-to-end #258 regression: a virtual-hosted (or access-point) request carries
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
			req := mustProviderReq(t, http.MethodGet, c.url)
			raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
			if err := p.AuthorizeAction(t.Context(), req, raw); err != nil {
				t.Fatalf("AuthorizeAction: %v", err)
			}
			if !slices.Equal(ev.got, c.want) {
				t.Errorf("evaluator received %v, want %v", ev.got, c.want)
			}
		})
	}
}

func TestProvider_AuthorizeAction_hostHeaderOverrideVirtualHosted(t *testing.T) {
	t.Parallel()
	// A model-supplied Host header override is the authority AWS actually serves
	// and SigV4-signs (transport.authorizeHostOverride pins it; the signer signs
	// req.Host). So a path-style URL plus a virtual-hosted Host override is a wire
	// vhost object GET and must classify to GetObject, not the bucket-level
	// ListObjects — closing the Host-override vector of #258.
	model := &ServiceModel{
		Dir: "s3", ARNNamespace: "s3", EndpointPrefix: "s3", SigningName: "s3",
		Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetObject":   {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}"},
			"ListObjects": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
			"ListBuckets": {HTTPMethod: "GET", URITemplate: "/"},
		},
	}
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
	// Path-style URL, but the model overrides Host to the virtual-hosted authority.
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/key.txt")
	req.Host = "my-bucket.s3.us-east-1.amazonaws.com"
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), req, raw); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}
	if !slices.Equal(ev.got, []string{"s3:GetObject"}) {
		t.Errorf("evaluator received %v, want [s3:GetObject] (Host override must drive vhost classification)", ev.got)
	}
}

// TestEffectiveAuthorityHost covers both branches of the helper directly, since
// [http.NewRequestWithContext] always populates req.Host from the URL host and the
// URL-host fallback branch would otherwise be unreachable in integration tests.
func TestEffectiveAuthorityHost(t *testing.T) {
	t.Parallel()
	t.Run("host override set", func(t *testing.T) {
		t.Parallel()
		req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
		req.Host = "my-bucket.s3.us-east-1.amazonaws.com"
		got := EffectiveAuthorityHost(req)
		if got != "my-bucket.s3.us-east-1.amazonaws.com" {
			t.Errorf("EffectiveAuthorityHost = %q, want %q", got, "my-bucket.s3.us-east-1.amazonaws.com")
		}
	})
	t.Run("host override empty falls back to URL host", func(t *testing.T) {
		t.Parallel()
		req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
		req.Host = ""
		got := EffectiveAuthorityHost(req)
		if got != "s3.us-east-1.amazonaws.com" {
			t.Errorf("EffectiveAuthorityHost = %q, want %q", got, "s3.us-east-1.amazonaws.com")
		}
	})
	t.Run("host override with explicit port strips the port", func(t *testing.T) {
		t.Parallel()
		// ParseHost rejects any colon-bearing host as an IP literal before it can
		// normalize, so the :port must be stripped here.
		req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/")
		req.Host = "my-bucket.s3.us-east-1.amazonaws.com:443"
		got := EffectiveAuthorityHost(req)
		if got != "my-bucket.s3.us-east-1.amazonaws.com" {
			t.Errorf("EffectiveAuthorityHost = %q, want %q", got, "my-bucket.s3.us-east-1.amazonaws.com")
		}
	})
	t.Run("explicit URL port carried in req.Host is stripped", func(t *testing.T) {
		t.Parallel()
		// http.NewRequestWithContext sets req.Host to the URL authority including the
		// explicit port, so the if-branch must strip it too.
		req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com:443/")
		got := EffectiveAuthorityHost(req)
		if got != "s3.us-east-1.amazonaws.com" {
			t.Errorf("EffectiveAuthorityHost = %q, want %q", got, "s3.us-east-1.amazonaws.com")
		}
	})
}

// TestProvider_AuthorizeAction_hostOverrideWithPort is the end-to-end regression
// guard for the port-stripping fix: a Host override carrying host:port must still
// classify (ParseHost rejects a colon-bearing host as an IP literal, so an
// unstripped port would fail action authorization for an otherwise-valid call).
func TestProvider_AuthorizeAction_hostOverrideWithPort(t *testing.T) {
	t.Parallel()
	model := &ServiceModel{
		Dir: "s3", ARNNamespace: "s3", EndpointPrefix: "s3", SigningName: "s3",
		Protocol: ProtocolRestXML,
		Operations: map[string]Operation{
			"GetObject":   {HTTPMethod: "GET", URITemplate: "/{Bucket}/{Key+}"},
			"ListObjects": {HTTPMethod: "GET", URITemplate: "/{Bucket}"},
		},
	}
	ev := &capturingEvaluator{allow: true}
	p := &Provider{
		models: &fakeArchive{models: []*ServiceModel{model}, err: nil},
		resolver: &opKeyedResolver{byOp: map[string]resolverResult{
			"GetObject":   {actions: []string{"s3:GetObject"}, source: SourceServiceRef},
			"ListObjects": {actions: []string{"s3:ListBucket"}, source: SourceServiceRef},
		}},
		evaluator: ev,
		policyARN: "arn:aws:iam::aws:policy/SecurityAudit",
	}
	req := mustProviderReq(t, http.MethodGet, "https://s3.us-east-1.amazonaws.com/key.txt")
	req.Host = "my-bucket.s3.us-east-1.amazonaws.com:443"
	raw := []byte(`{"aws_auth":{"service":"s3","region":"us-east-1"}}`)
	if err := p.AuthorizeAction(t.Context(), req, raw); err != nil {
		t.Fatalf("AuthorizeAction: %v (the :port must be stripped before ParseHost)", err)
	}
	if !slices.Equal(ev.got, []string{"s3:GetObject"}) {
		t.Errorf("evaluator received %v, want [s3:GetObject]", ev.got)
	}
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

// capturingEvaluator records the action set it received and always allows.
type capturingEvaluator struct {
	allow bool
	got   []string
}

func (e *capturingEvaluator) AllowedAll(_ context.Context, actions []string) (bool, error) {
	e.got = actions
	return e.allow, nil
}

func mustProviderReq(t *testing.T, method, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, raw, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
