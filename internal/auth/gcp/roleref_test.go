package gcp_test

import (
	"errors"
	"testing"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

func TestParseRoleReference(t *testing.T) {
	t.Parallel()

	accept := []struct {
		role string
		kind gcphardening.RoleRefKind
	}{
		{"roles/viewer", gcphardening.RoleRefPredefined},
		{"roles/iam.securityReviewer", gcphardening.RoleRefPredefined},
		{"projects/p/roles/r", gcphardening.RoleRefProjectCustom},
		{"projects/my-proj/roles/customViewer", gcphardening.RoleRefProjectCustom},
		{"projects/123/roles/x", gcphardening.RoleRefProjectCustom},
		{"organizations/o/roles/r", gcphardening.RoleRefOrgCustom},
		{"organizations/0/roles/x", gcphardening.RoleRefOrgCustom},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.role, func(t *testing.T) {
			t.Parallel()
			kind, err := gcphardening.ParseRoleReference(tc.role)
			if err != nil {
				t.Fatalf("ParseRoleReference(%q) error = %v, want nil", tc.role, err)
			}
			if kind != tc.kind {
				t.Errorf("ParseRoleReference(%q) kind = %v, want %v", tc.role, kind, tc.kind)
			}
		})
	}

	reject := []string{
		"", "roles", "roles/", "roles/a/b",
		"projects//roles/x", "projects/p/roles/", "projects/p/roles", "projects/p/r",
		"organizations//roles/x", "organizations/o/roles/", "organizations/o/r",
		"folders/f/roles/r", "garbage", "/roles/x", "projects/p/roles/r/extra",
	}
	for _, role := range reject {
		t.Run("reject/"+role, func(t *testing.T) {
			t.Parallel()
			if _, err := gcphardening.ParseRoleReference(role); !errors.Is(err, gcphardening.ErrInvalidRoleRef) {
				t.Errorf("ParseRoleReference(%q) err = %v, want ErrInvalidRoleRef", role, err)
			}
		})
	}
}
