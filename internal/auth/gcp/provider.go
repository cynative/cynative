package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Provider is the composed pure Layer-2 provider that internal/auth/gcp.go
// delegates to via AuthorizeAction. Layer 1 (credential scoping) and the
// scoped token source live in the parent gcpProvider.
type Provider struct {
	catalog Catalog
	perms   PermissionResolver
	eval    *roleEvaluator
	role    string
}

// NewProvider constructs the composed provider with its collaborators.
func NewProvider(
	catalog Catalog,
	perms PermissionResolver,
	eval *roleEvaluator,
	role string,
) *Provider {
	return &Provider{
		catalog: catalog,
		perms:   perms,
		eval:    eval,
		role:    role,
	}
}

// gcpArgsShape decodes only the gcp_auth.service field Layer 2 needs; the full
// wire shape is auth.GCPAuthArgs (re-declared because internal/auth/gcp cannot
// import internal/auth — the parent imports this package).
type gcpArgsShape struct {
	GCPAuth *struct {
		Service string `json:"service"`
	} `json:"gcp_auth"`
}

// AuthorizeAction runs the Layer 2 pipeline. The service is derived from the
// request HOST only (never the claim). Fails closed on any unresolved step.
// For www.googleapis.com, the service is resolved from the PATH (via
// resolveService) and then verified against the gcp_auth.service claim here —
// because Layer 3 (AuthorizesHost) cannot do that check without the path.
func (p *Provider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	var args gcpArgsShape
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return fmt.Errorf("gcp_hardening: parse gcp_auth: %w", err)
	}

	if args.GCPAuth == nil || args.GCPAuth.Service == "" {
		return errors.New("gcp_hardening: gcp_auth.service is required")
	}

	host := strings.ToLower(req.URL.Hostname())
	isWWW := host == wwwGoogleapisHost

	service, err := p.resolveService(ctx, req)
	if err != nil {
		return err
	}

	// For www.googleapis.com Layer 3 cannot verify the claim (no path). Layer 2
	// owns the check: the path-resolved service must match gcp_auth.service.
	// The claim is COMPARED against the resolved service, never used as a source.
	if isWWW {
		if !strings.EqualFold(service, args.GCPAuth.Service) {
			return fmt.Errorf("%w: www path resolves service %q but gcp_auth.service is %q",
				ErrHostClaimMismatch, service, args.GCPAuth.Service)
		}
	}

	idx, err := p.catalog.MethodIndex(ctx, service)
	if err != nil {
		return err
	}

	methodID, err := Classify(idx, req)
	if err != nil {
		return err
	}

	perms, src := p.perms.Resolve(ctx, methodID)
	if src == SourceNone {
		return fmt.Errorf("%w: method %q (no derived or dataset permission)", ErrPermissionUnresolved, methodID)
	}

	if !p.eval.AllowedAll(perms) {
		return fmt.Errorf("%w: %v not granted by role %s", ErrPermissionDenied, perms, p.role)
	}

	return nil
}

// resolveService derives the service from the request HOST only, handling the
// www.googleapis.com compound case by falling back to path-based resolution.
func (p *Provider) resolveService(ctx context.Context, req *http.Request) (string, error) {
	host := strings.ToLower(req.URL.Hostname())

	parsed, err := ParseHost(host)
	if err != nil {
		return "", err
	}

	if parsed.Service == wwwCompoundSentinel {
		svc, ok := p.catalog.ResolveWWWService(ctx, req.URL.Path)
		if !ok {
			return "", fmt.Errorf("%w: %q (www path service not in catalog)", ErrHostPattern, req.URL.Path)
		}

		return svc, nil
	}

	return p.catalog.ResolveService(ctx, parsed, host)
}
