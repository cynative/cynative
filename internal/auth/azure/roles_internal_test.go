package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

func TestMatchesRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rd   *armauthorization.RoleDefinition
		want string
		ok   bool
	}{
		{
			name: "guid name match case-insensitive",
			rd: &armauthorization.RoleDefinition{
				Name:       new("ACDD72A7-3385-48EF-BD42-F606FBA81AE7"),
				Properties: &armauthorization.RoleDefinitionProperties{},
			},
			want: "acdd72a7-3385-48ef-bd42-f606fba81ae7",
			ok:   true,
		},
		{
			name: "rolename match case-insensitive",
			rd: &armauthorization.RoleDefinition{
				Properties: &armauthorization.RoleDefinitionProperties{RoleName: new("Reader")},
			},
			want: "reader",
			ok:   true,
		},
		{
			name: "neither matches",
			rd: &armauthorization.RoleDefinition{
				Name:       new("x"),
				Properties: &armauthorization.RoleDefinitionProperties{RoleName: new("Contributor")},
			},
			want: "Reader",
			ok:   false,
		},
		{
			name: "both pointer fields nil no panic",
			rd:   &armauthorization.RoleDefinition{Properties: &armauthorization.RoleDefinitionProperties{}},
			want: "Reader",
			ok:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := matchesRole(tc.rd, tc.want); got != tc.ok {
				t.Errorf("matchesRole = %v, want %v", got, tc.ok)
			}
		})
	}
}

func TestFlattenPermissions(t *testing.T) {
	t.Parallel()
	t.Run("single block", func(t *testing.T) {
		t.Parallel()
		rd := &armauthorization.RoleDefinition{Properties: &armauthorization.RoleDefinitionProperties{
			Permissions: []*armauthorization.Permission{
				{Actions: []*string{new("*/read")}, NotActions: []*string{new("*/secret/read")}},
			},
		}}
		got := flattenPermissions(rd)
		if len(got.Actions) != 1 || got.Actions[0] != "*/read" {
			t.Errorf("Actions = %v", got.Actions)
		}
		if len(got.NotActions) != 1 || got.NotActions[0] != "*/secret/read" {
			t.Errorf("NotActions = %v", got.NotActions)
		}
	})
	t.Run("multi block union with nil skip", func(t *testing.T) {
		t.Parallel()
		rd := &armauthorization.RoleDefinition{Properties: &armauthorization.RoleDefinitionProperties{
			Permissions: []*armauthorization.Permission{
				{Actions: []*string{new("a/read")}},
				nil,
				{Actions: []*string{new("b/read")}, NotActions: []*string{new("b/write")}},
			},
		}}
		got := flattenPermissions(rd)
		if len(got.Actions) != 2 {
			t.Errorf("union Actions = %v, want 2", got.Actions)
		}
		if len(got.NotActions) != 1 {
			t.Errorf("union NotActions = %v, want 1", got.NotActions)
		}
	})
	t.Run("empty permissions zero", func(t *testing.T) {
		t.Parallel()
		rd := &armauthorization.RoleDefinition{Properties: &armauthorization.RoleDefinitionProperties{}}
		got := flattenPermissions(rd)
		if got.Actions != nil || got.NotActions != nil {
			t.Errorf("empty = %+v, want zero", got)
		}
	})
}

func TestDerefAll(t *testing.T) {
	t.Parallel()
	t.Run("normal and nil skip", func(t *testing.T) {
		t.Parallel()
		got := derefAll([]*string{new("a"), nil, new("b")})
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Errorf("derefAll = %v, want [a b]", got)
		}
	})
	t.Run("empty input non-nil len0", func(t *testing.T) {
		t.Parallel()
		got := derefAll(nil)
		if got == nil || len(got) != 0 {
			t.Errorf("derefAll(nil) = %v, want non-nil len 0", got)
		}
	})
	t.Run("all nil", func(t *testing.T) {
		t.Parallel()
		got := derefAll([]*string{nil, nil})
		if len(got) != 0 {
			t.Errorf("derefAll(all nil) = %v, want len 0", got)
		}
	})
}

func TestSelectRolePermissions(t *testing.T) {
	t.Parallel()
	mk := func(roleName string, actions ...string) *armauthorization.RoleDefinition {
		acts := make([]*string, 0, len(actions))
		for _, a := range actions {
			acts = append(acts, new(a))
		}
		return &armauthorization.RoleDefinition{Properties: &armauthorization.RoleDefinitionProperties{
			RoleName:    new(roleName),
			Permissions: []*armauthorization.Permission{{Actions: acts}},
		}}
	}
	t.Run("found on first", func(t *testing.T) {
		t.Parallel()
		perms, ok := selectRolePermissions([]*armauthorization.RoleDefinition{mk("Reader", "*/read")}, "Reader")
		if !ok || len(perms.Actions) != 1 || perms.Actions[0] != "*/read" {
			t.Errorf("got %+v ok=%v", perms, ok)
		}
	})
	t.Run("found after nil and nil-properties skips", func(t *testing.T) {
		t.Parallel()
		vals := []*armauthorization.RoleDefinition{
			nil,
			{Properties: nil, Name: new("x")},
			mk("Reader", "*/read"),
		}
		perms, ok := selectRolePermissions(vals, "Reader")
		if !ok || len(perms.Actions) != 1 {
			t.Errorf("got %+v ok=%v", perms, ok)
		}
	})
	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		perms, ok := selectRolePermissions([]*armauthorization.RoleDefinition{mk("Contributor", "*")}, "Reader")
		if ok || len(perms.Actions) != 0 {
			t.Errorf("got %+v ok=%v, want zero,false", perms, ok)
		}
	})
}
