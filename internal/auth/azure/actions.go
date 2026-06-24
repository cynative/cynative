package azure

import (
	"context"
	"fmt"
	"strings"
)

// ValidateAction confirms the derived Action exists in the official
// providerOperations catalog with isDataAction == false. Membership and the
// data-plane flag are looked up via the catalog's LookupOperation (the only
// source — never iamlive). Pure modulo the injected Catalog port.
//
// Safety against the listKeys/readonlykeys landmines lives in DeriveAction (the
// structural /action verb + ambiguity-deny); ValidateAction is the catalog
// existence + data-plane filter only.
func ValidateAction(ctx context.Context, cat Catalog, a Action) error {
	// Normalize to lowercase: Azure RBAC is case-insensitive; the catalog
	// implementation and fakes key on lowercased names. DeriveAction (the only
	// source of Actions reaching here) always populates all three fields, so the
	// canonical Full is just their lowercased concatenation.
	namespace := strings.ToLower(a.Namespace)
	typePath := strings.ToLower(a.ResourceType)
	token := strings.ToLower(a.Verb)
	_, byVerb, err := cat.LookupOperation(ctx, namespace, typePath, token)
	if err != nil {
		return fmt.Errorf("%w: validate %q: %w", ErrCatalogUnavailable, a.Full, err)
	}

	isData, exists := byVerb[token]
	if !exists {
		return fmt.Errorf("%w: %q absent from providerOperations catalog", ErrActionUnresolved, a.Full)
	}

	if isData {
		return fmt.Errorf("%w: %q is a dataAction", ErrDataPlaneNotSupported, a.Full)
	}

	return nil
}
