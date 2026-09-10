package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/auth/authreq"
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

// argsShape decodes no field: only the presence of the aws_auth block matters
// here, since the service is derived from the request host via ParseHost.
type argsShape struct{}

// AuthorizeAction resolves the prefix to candidate models, classifies the
// operation against each, and requires the conservative UNION of every matched
// candidate's IAM actions to be authorized. Candidates come from two places: a
// prefix collision (e.g. email→ses/sesv2) yields one per model, and a REST
// request that ties between operations of one model yields one per tied
// operation. A permissionless candidate (the operation needs no IAM
// permission, e.g. sts:GetCallerIdentity) counts as matched but contributes no
// required action. Fail closed on any unresolved candidate.
func (p *Provider) AuthorizeAction(ctx context.Context, v authreq.View, args authreq.ProviderArgs) error {
	awsAuth, err := authreq.Parse[argsShape](args)
	if err != nil {
		return fmt.Errorf("aws_hardening: %w", err)
	}
	if awsAuth == nil {
		return errors.New("aws_hardening: aws_auth is required")
	}
	parsed, err := ParseHost(v.Hostname)
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
		ops, opErr := ClassifyOperation(model, v, parsed)
		if opErr != nil {
			// Every classifier error means this candidate does not serve the
			// operation (ClassifyOperation only ever wraps ErrClassifierUnknownOp),
			// so skip it; the matched==0 guard below fails closed if none serve.
			continue
		}
		matched++
		actions, actErr := p.requiredActions(ctx, model, ops)
		if actErr != nil {
			return actErr
		}
		required = appendUnique(required, actions...)
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

// requiredActions resolves every classified candidate of one model to its IAM
// actions. A permissionless candidate contributes nothing; a candidate no tier
// can resolve fails closed whatever its siblings resolve to, so a tie can never
// be authorized on one candidate alone.
func (p *Provider) requiredActions(ctx context.Context, model *ServiceModel, ops []string) ([]string, error) {
	var out []string
	for _, op := range ops {
		actions, src := p.resolver.Resolve(ctx, model, op)
		if src == SourcePermissionless {
			continue // operation needs no IAM permission; nothing to authorize.
		}
		if src == SourceNone || len(actions) == 0 {
			return nil, fmt.Errorf("%w: %s:%s", ErrActionUnresolved, model.Dir, op)
		}
		out = append(out, actions...)
	}
	return out, nil
}

// appendUnique appends the actions not already in required, keeping first-seen
// order so the evaluator and the denial message stay deterministic and name
// each action once however many candidates share it.
func appendUnique(required []string, actions ...string) []string {
	for _, a := range actions {
		if !slices.Contains(required, a) {
			required = append(required, a)
		}
	}
	return required
}
