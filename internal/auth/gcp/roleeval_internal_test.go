package gcp

import (
	"context"
	"errors"
	"testing"
)

func TestRoleEvaluatorAllowedAll(t *testing.T) {
	t.Parallel()

	eval := newRoleEvaluator(map[string]bool{
		"compute.instances.list":       true,
		"resourcemanager.projects.get": true,
		"storage.buckets.list":         true,
	})

	tests := []struct {
		name  string
		perms []string
		want  bool
	}{
		{name: "single allowed", perms: []string{"compute.instances.list"}, want: true},
		{name: "all allowed", perms: []string{"compute.instances.list", "storage.buckets.list"}, want: true},
		{name: "one denied", perms: []string{"compute.instances.list", "iam.serviceAccounts.list"}, want: false},
		{name: "empty allowed (permissionless)", perms: nil, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := eval.AllowedAll(tc.perms); got != tc.want {
				t.Errorf("AllowedAll(%v) = %v, want %v", tc.perms, got, tc.want)
			}
		})
	}
}

func TestFetchRolePermissions(t *testing.T) {
	t.Parallel()

	client := &iamRolesClientMock{
		GetRoleFunc: func(_ context.Context, role string) (RoleDefinition, error) {
			if role == "roles/viewer" {
				return RoleDefinition{
					IncludedPermissions: []string{"compute.instances.list", "storage.buckets.list"},
				}, nil
			}
			return RoleDefinition{}, errors.New("unknown role")
		},
	}
	granted, err := FetchRolePermissions(context.Background(), client, "roles/viewer")
	if err != nil {
		t.Fatalf("FetchRolePermissions: %v", err)
	}
	for _, want := range []string{"compute.instances.list", "storage.buckets.list"} {
		if !granted[want] {
			t.Errorf("granted missing %q", want)
		}
	}
}

func TestFetchRolePermissionsFailClosed(t *testing.T) {
	t.Parallel()

	client := &iamRolesClientMock{
		GetRoleFunc: func(context.Context, string) (RoleDefinition, error) {
			return RoleDefinition{}, errors.New("403")
		},
	}
	if _, err := FetchRolePermissions(
		context.Background(), client, "roles/viewer",
	); !errors.Is(err, ErrRoleFetchFailed) {
		t.Fatalf("want ErrRoleFetchFailed, got %v", err)
	}
}

func TestFetchRolePermissionsDisabled(t *testing.T) {
	t.Parallel()

	perms := []string{"compute.instances.list"}
	disabled := []struct {
		name string
		def  RoleDefinition
	}{
		{"stage_DISABLED", RoleDefinition{IncludedPermissions: perms, Stage: "DISABLED"}},
		{"deleted_only", RoleDefinition{IncludedPermissions: perms, Deleted: true}},
		{"disabled_and_deleted", RoleDefinition{IncludedPermissions: perms, Stage: "DISABLED", Deleted: true}},
	}
	for _, tc := range disabled {
		t.Run("denied/"+tc.name, func(t *testing.T) {
			t.Parallel()
			client := &iamRolesClientMock{
				GetRoleFunc: func(context.Context, string) (RoleDefinition, error) { return tc.def, nil },
			}
			if _, err := FetchRolePermissions(
				context.Background(), client, "projects/p/roles/r",
			); !errors.Is(err, ErrRoleDisabled) {
				t.Fatalf("%s: err = %v, want ErrRoleDisabled", tc.name, err)
			}
		})
	}

	// Empty stage and non-DISABLED stages resolve normally (a custom role may omit
	// stage; DEPRECATED/GA/BETA/ALPHA/EAP are usable).
	for _, stage := range []string{"", "GA", "BETA", "ALPHA", "EAP", "DEPRECATED"} {
		t.Run("usable/"+stage, func(t *testing.T) {
			t.Parallel()
			client := &iamRolesClientMock{
				GetRoleFunc: func(context.Context, string) (RoleDefinition, error) {
					return RoleDefinition{IncludedPermissions: []string{"storage.buckets.list"}, Stage: stage}, nil
				},
			}
			granted, err := FetchRolePermissions(context.Background(), client, "roles/x")
			if err != nil {
				t.Fatalf("stage %q: unexpected err %v", stage, err)
			}
			if !granted["storage.buckets.list"] {
				t.Errorf("stage %q: missing granted permission", stage)
			}
		})
	}
}

func TestAllowedAllNoWildcardExpansion(t *testing.T) {
	t.Parallel()
	// A custom role granting a literal "*" must authorize nothing — includedPermissions
	// are exact map keys, never wildcards.
	eval := newRoleEvaluator(map[string]bool{"*": true})
	if eval.AllowedAll([]string{"compute.instances.list"}) {
		t.Error("AllowedAll authorized a real permission against a literal \"*\" grant")
	}
}
