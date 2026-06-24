package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Provider is the composed pure Layer-2 provider that internal/auth/azure.go
// delegates to via AuthorizeAction. Azure has no Layer-1 credential
// downscoping primitive, so Layer 2 is the sole role-definition enforcement.
type Provider struct {
	catalog        Catalog
	eval           RoleEvaluator
	roleDefinition string
}

// NewProvider constructs the composed provider with its collaborators.
func NewProvider(cat Catalog, eval RoleEvaluator, roleDefinition string) *Provider {
	return &Provider{
		catalog:        cat,
		eval:           eval,
		roleDefinition: roleDefinition,
	}
}

// azureArgsShape decodes only the service claim Layer 2 verifies against the URL
// path; the cloud claim is verified separately at Layer 3 (azure.go AuthorizesHost).
type azureArgsShape struct {
	AzureAuth *struct {
		Service string `json:"service"`
	} `json:"azure_auth"`
}

// AuthorizeAction runs the Layer 2 pipeline:
// DeriveAction → verify azure_auth.service == path namespace →
// ValidateAction (catalog) → eval.Allowed (role-definition membership).
// The service is derived from the URL path (the last /providers/ namespace);
// azure_auth.service is only verified against it, never used as a source.
// Fails closed on any unresolved step.
func (p *Provider) AuthorizeAction(ctx context.Context, req *http.Request, rawArgs json.RawMessage) error {
	var args azureArgsShape
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return fmt.Errorf("azure_hardening: parse azure_auth: %w", err)
	}
	if args.AzureAuth == nil || args.AzureAuth.Service == "" {
		return errors.New("azure_hardening: azure_auth.service is required")
	}

	// Layer 2: structural action derivation (service from URL path only).
	action, err := DeriveAction(ctx, req, p.catalog)
	if err != nil {
		return err
	}

	// Verify the model's claimed service against the path-derived namespace.
	if !strings.EqualFold(action.Namespace, args.AzureAuth.Service) {
		return fmt.Errorf("%w: path namespace %q != azure_auth.service %q",
			ErrHostClaimMismatch, action.Namespace, args.AzureAuth.Service)
	}

	// Catalog validation: Action exists, isDataAction=false.
	if err = ValidateAction(ctx, p.catalog, action); err != nil {
		return err
	}

	// Role-definition membership.
	if !p.eval.Allowed(action) {
		return fmt.Errorf("%w: %q not allowed by role definition %q", ErrActionDenied, action.Full, p.roleDefinition)
	}

	return nil
}
