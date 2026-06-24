package azure

import (
	"context"
	"errors"
	"testing"
)

// validatingCatalog is a Catalog fake whose LookupOperation answers the
// existence + isDataAction question for ValidateAction. Keyed by the lowercased
// Full action string.
type validatingCatalog struct {
	exists map[string]bool
	data   map[string]bool
}

func (v validatingCatalog) ResolveCloud(_ context.Context, p ParsedHost) (ParsedHost, error) {
	return p, nil
}
func (v validatingCatalog) ResourceTypes(context.Context, string) ([]string, error) { return nil, nil }

func (v validatingCatalog) LookupOperation(
	_ context.Context, namespace, resourceTypePath, verbToken string,
) ([]string, map[string]bool, error) {
	full := namespace + "/" + resourceTypePath + "/" + verbToken
	if !v.exists[full] {
		return nil, map[string]bool{}, nil
	}

	return []string{verbToken}, map[string]bool{verbToken: v.data[full]}, nil
}

func validationCatalog() validatingCatalog {
	return validatingCatalog{
		exists: map[string]bool{
			"microsoft.compute/virtualmachines/read":            true,
			"microsoft.storage/storageaccounts/listkeys/action": true,
			"microsoft.keyvault/vaults/secrets/read":            true, // a dataAction
		},
		data: map[string]bool{
			"microsoft.keyvault/vaults/secrets/read": true,
		},
	}
}

func TestValidateAction(t *testing.T) {
	t.Parallel()

	cat := validationCatalog()
	tests := []struct {
		name    string
		action  Action
		wantErr error
	}{
		{
			name: "control-plane read exists, not data → ok",
			action: Action{
				Namespace:    "Microsoft.Compute",
				ResourceType: "virtualMachines",
				Verb:         "read",
				Full:         "Microsoft.Compute/virtualMachines/read",
			},
		},
		{
			name: "listKeys /action exists, isDataAction=false → ok (structural verb gates safety, not this)",
			action: Action{
				Namespace:    "Microsoft.Storage",
				ResourceType: "storageAccounts",
				Verb:         "listKeys/action",
				Full:         "Microsoft.Storage/storageAccounts/listKeys/action",
			},
		},
		{
			name:    "absent from catalog → unresolved",
			action:  Action{Full: "Microsoft.Fake/widgets/read"},
			wantErr: ErrActionUnresolved,
		},
		{
			name: "isDataAction=true → data-plane not supported",
			action: Action{
				Namespace:    "Microsoft.KeyVault",
				ResourceType: "vaults/secrets",
				Verb:         "read",
				Full:         "Microsoft.KeyVault/vaults/secrets/read",
			},
			wantErr: ErrDataPlaneNotSupported,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateAction(context.Background(), cat, tc.action)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ValidateAction err = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ValidateAction: %v", err)
			}
		})
	}
}

// TestValidateActionCaseInsensitive confirms a differently-cased Full still
// resolves (Azure RBAC is case-insensitive).
func TestValidateActionCaseInsensitive(t *testing.T) {
	t.Parallel()

	cat := validationCatalog()
	if err := ValidateAction(context.Background(), cat, Action{
		Namespace: "microsoft.compute", ResourceType: "virtualmachines", Verb: "READ",
		Full: "microsoft.compute/virtualmachines/READ",
	}); err != nil {
		t.Fatalf("case-insensitive validate: %v", err)
	}
}

// errorCatalog is a Catalog fake whose LookupOperation always returns an error.
type errorCatalog struct{}

func (e errorCatalog) ResolveCloud(_ context.Context, p ParsedHost) (ParsedHost, error) {
	return p, nil
}
func (e errorCatalog) ResourceTypes(context.Context, string) ([]string, error) { return nil, nil }
func (e errorCatalog) LookupOperation(
	context.Context, string, string, string,
) ([]string, map[string]bool, error) {
	return nil, nil, ErrCatalogUnavailable
}

// TestValidateActionCatalogError confirms that a LookupOperation error surfaces
// as ErrCatalogUnavailable.
func TestValidateActionCatalogError(t *testing.T) {
	t.Parallel()

	err := ValidateAction(context.Background(), errorCatalog{}, Action{
		Namespace: "Microsoft.Compute", ResourceType: "virtualMachines", Verb: "read",
		Full: "Microsoft.Compute/virtualMachines/read",
	})
	if !errors.Is(err, ErrCatalogUnavailable) {
		t.Fatalf("expected ErrCatalogUnavailable, got %v", err)
	}
}
