package azure_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

// stubTokenCredential is a fake azcore.TokenCredential for tests that don't
// require real Azure auth.
type stubTokenCredential struct{}

func (stubTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "stub"}, nil //nolint:exhaustruct // expiry zero is fine for tests
}

// TestRolesShellRolePermissions drives the real role client against an httptest
// server returning the ARM roleDefinitions list-by-name + get shapes. Not gated.
func TestRolesShellRolePermissions(t *testing.T) {
	mux := http.NewServeMux()
	// roleDefinitions list filtered by roleName → returns the GUID + permissions.
	mux.HandleFunc("/providers/Microsoft.Authorization/roleDefinitions",
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(
				[]byte(
					`{"value":[{"id":"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7","name":"acdd72a7-3385-48ef-bd42-f606fba81ae7","properties":{"roleName":"Reader","permissions":[{"actions":["*/read"],"notActions":[],"dataActions":[],"notDataActions":[]}]}}]}`,
				),
			)
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := azurehardening.NewRoleClient(azurehardening.RoleClientConfig{
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
		Credential: stubTokenCredential{},
	})
	if err != nil {
		t.Fatalf("NewRoleClient: %v", err)
	}

	perms, err := client.RolePermissions(context.Background(), "Reader")
	if err != nil {
		t.Fatalf("RolePermissions: %v", err)
	}
	if len(perms.Actions) != 1 || perms.Actions[0] != "*/read" {
		t.Fatalf("Reader actions = %v, want [*/read]", perms.Actions)
	}
}
