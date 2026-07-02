package config_test

import (
	"testing"

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
