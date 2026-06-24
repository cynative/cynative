package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ModelResolver resolves a host endpoint prefix to every modeled service that
// answers on it (more than one ⇒ a collision).
type ModelResolver interface {
	Resolve(ctx context.Context, prefix string) ([]*ServiceModel, error)
}

// Resolver maps a classified operation in a specific model to its IAM action
// set and the tier that produced it.
type Resolver interface {
	Resolve(ctx context.Context, model *ServiceModel, op string) ([]string, ActionSource)
}

// Evaluator is the policy-evaluator port. Same rationale as ModelResolver.
type Evaluator interface {
	AllowedAll(ctx context.Context, actions []string) (bool, error)
}

// Provider is the composed pure provider that internal/auth/aws.go delegates
// to. Owns Layer 2 + Layer 3 enforcement logic; Layer 1 (credential scoping)
// and S3 header injection live in the parent awsProvider.
type Provider struct {
	models    ModelResolver
	resolver  Resolver
	evaluator Evaluator
	policyARN string
}

// NewProvider constructs the composed provider with the supplied collaborators.
func NewProvider(models ModelResolver, resolver Resolver, evaluator Evaluator, policyARN string) *Provider {
	return &Provider{
		models:    models,
		resolver:  resolver,
		evaluator: evaluator,
		policyARN: policyARN,
	}
}

// argsShape decodes only whether the aws_auth block is present; the service is
// derived from the request host via ParseHost, not from these args.
type argsShape struct {
	AWSAuth *struct{} `json:"aws_auth"`
}

// AuthorizeAction resolves the prefix to candidate models, classifies the
// operation against each, and requires the conservative UNION of every matched
// candidate's IAM actions to be authorized. A permissionless candidate (the
// operation needs no IAM permission, e.g. sts:GetCallerIdentity) counts as
// matched but contributes no required action. Multiple matches occur only for
// prefix collisions (e.g. email→ses/sesv2). Fail closed on any unresolved
// candidate.
func (p *Provider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	var args argsShape
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return fmt.Errorf("aws_hardening: parse aws_auth: %w", err)
	}
	if args.AWSAuth == nil {
		return errors.New("aws_hardening: aws_auth is required")
	}
	parsed, err := ParseHost(strings.ToLower(EffectiveAuthorityHost(req)))
	if err != nil {
		return err
	}
	models, err := p.models.Resolve(ctx, parsed.Service)
	if err != nil {
		return err
	}

	var required []string
	matched := 0
	for _, model := range models {
		if !strings.EqualFold(model.EndpointPrefix, parsed.Service) {
			continue // defensive: index/parse drift.
		}
		op, opErr := ClassifyOperation(model, req, parsed)
		if opErr != nil {
			// Every classifier error means this candidate does not serve the
			// operation (ClassifyOperation only ever wraps ErrClassifierUnknownOp),
			// so skip it; the matched==0 guard below fails closed if none serve.
			continue
		}
		matched++
		actions, src := p.resolver.Resolve(ctx, model, op)
		if src == SourcePermissionless {
			continue // operation needs no IAM permission; nothing to authorize.
		}
		if src == SourceNone || len(actions) == 0 {
			return fmt.Errorf("%w: %s:%s", ErrActionUnresolved, model.Dir, op)
		}
		required = append(required, actions...)
	}
	if matched == 0 {
		return fmt.Errorf("%w: no candidate serves the request for %q", ErrActionUnresolved, parsed.Service)
	}

	allowed, err := p.evaluator.AllowedAll(ctx, required)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: %v denied by policy %s", ErrPolicyDenied, required, p.policyARN)
	}
	return nil
}

// EffectiveAuthorityHost returns the host AWS actually serves and SigV4-signs:
// the model-supplied Host header override (req.Host) when present, otherwise the
// URL host. The transport authorizes the override (authorizeHostOverride) and the
// signer signs req.Host, so the override is the wire authority and action
// classification must follow it — otherwise a path-style URL plus a virtual-hosted
// Host override would be classified path-style and gate the wrong IAM action
// (mirrors the GitHub provider's served-authority handling). The :port (and any
// IPv6 brackets) are stripped via (*url.URL).Hostname — the same normalization
// req.URL.Hostname already applies — because ParseHost rejects any colon-bearing
// host as an IP literal before it can normalize. Pure: no I/O.
func EffectiveAuthorityHost(req *http.Request) string {
	if req.Host != "" {
		return (&url.URL{Host: req.Host}).Hostname()
	}
	return req.URL.Hostname()
}

// ResolveSigningName maps a request host to the SigV4 signing name declared by
// the service model answering on it (the aws.auth#sigv4 name, which differs
// from the endpoint prefix for ECR and a few others). It fails closed with
// ErrSigningNameUnresolved when no modeled service serves the host's endpoint
// prefix or when colliding candidates disagree on the signing name. Pure: all
// I/O goes through the injected ModelResolver.
func (p *Provider) ResolveSigningName(ctx context.Context, host string) (string, error) {
	parsed, err := ParseHost(strings.ToLower(host))
	if err != nil {
		return "", err
	}
	models, err := p.models.Resolve(ctx, parsed.Service)
	if err != nil {
		return "", err
	}
	name := ""
	for _, model := range models {
		if !strings.EqualFold(model.EndpointPrefix, parsed.Service) {
			continue // defensive: index/parse drift (mirrors AuthorizeAction).
		}
		switch {
		case name == "":
			name = model.SigningName
		case !strings.EqualFold(name, model.SigningName):
			return "", fmt.Errorf("%w: %q resolves to conflicting signing names %q and %q",
				ErrSigningNameUnresolved, parsed.Service, name, model.SigningName)
		}
	}
	if name == "" {
		return "", fmt.Errorf("%w: no model serves %q", ErrSigningNameUnresolved, parsed.Service)
	}
	return name, nil
}
