package config_test

import (
	"testing"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
	"github.com/cynative/cynative/internal/config"
)

func TestValidateGCPRole(t *testing.T) {
	t.Parallel()

	accept := []string{
		"", // empty deferred to the `required` tag.
		"roles/viewer", "roles/iam.securityReviewer",
		"projects/p/roles/r", "projects/my-proj/roles/customViewer",
		"organizations/o/roles/r", "organizations/0/roles/x",
	}
	for _, role := range accept {
		t.Run("accept/"+role, func(t *testing.T) {
			t.Parallel()
			if err := config.ValidateGCPRole(role); err != nil {
				t.Errorf("ValidateGCPRole(%q) = %v, want nil", role, err)
			}
		})
	}

	reject := []string{
		"roles", "roles/", "roles/a/b",
		"projects//roles/x", "projects/p/roles/", "projects/p/r",
		"organizations//roles/x", "folders/f/roles/r", "garbage", "/roles/x",
	}
	for _, role := range reject {
		t.Run("reject/"+role, func(t *testing.T) {
			t.Parallel()
			if err := config.ValidateGCPRole(role); err == nil {
				t.Errorf("ValidateGCPRole(%q) = nil, want error", role)
			}
		})
	}
}

// TestGCPRoleValidationParity pins config's inline validator to the authoritative
// gcp.ParseRoleReference for every non-empty role string, so the two cannot drift
// (a config-accepted form the shell can't dispatch would fail closed at runtime
// instead of giving a clear config error).
func TestGCPRoleValidationParity(t *testing.T) {
	t.Parallel()

	roles := []string{
		"roles/viewer", "roles/iam.securityReviewer",
		"projects/p/roles/r", "projects/my-proj/roles/customViewer", "projects/123/roles/x",
		"organizations/o/roles/r", "organizations/0/roles/x",
		"roles", "roles/", "roles/a/b",
		"projects//roles/x", "projects/p/roles/", "projects/p/roles", "projects/p/r",
		"organizations//roles/x", "organizations/o/roles/", "organizations/o/r",
		"folders/f/roles/r", "garbage", "/roles/x", "projects/p/roles/r/extra",
	}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			cfgOK := config.ValidateGCPRole(role) == nil
			_, perr := gcphardening.ParseRoleReference(role)
			parserOK := perr == nil
			if cfgOK != parserOK {
				t.Errorf("parity drift for %q: config accepts=%v, parser accepts=%v", role, cfgOK, parserOK)
			}
		})
	}
}
