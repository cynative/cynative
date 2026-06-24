package azure

import (
	"context"
	"errors"
	"testing"
)

func readerPerms() RolePermissions {
	return RolePermissions{Actions: []string{"*/read"}}
}

func TestMatchPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		action  string
		want    bool
	}{
		{
			name:    "*/read matches a read",
			pattern: "*/read",
			action:  "Microsoft.Compute/virtualMachines/read",
			want:    true,
		},
		{
			name:    "*/read spans slashes",
			pattern: "*/read",
			action:  "Microsoft.OperationalInsights/workspaces/providers/Microsoft.SecurityInsights/incidents/read",
			want:    true,
		},
		{
			name:    "*/read does NOT match /action",
			pattern: "*/read",
			action:  "Microsoft.Storage/storageAccounts/listKeys/action",
			want:    false,
		},
		{name: "bare * matches anything", pattern: "*", action: "Microsoft.Compute/virtualMachines/delete", want: true},
		{
			name:    "case-insensitive",
			pattern: "Microsoft.Compute/*/read",
			action:  "microsoft.compute/virtualmachines/READ",
			want:    true,
		},
		{
			name:    "anchored: no prefix leak",
			pattern: "Microsoft.Compute/virtualMachines/read",
			action:  "xMicrosoft.Compute/virtualMachines/read",
			want:    false,
		},
		{
			name:    "anchored: no suffix leak",
			pattern: "*/read",
			action:  "Microsoft.Compute/virtualMachines/readWrite",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := matchPattern(tc.pattern, tc.action); got != tc.want {
				t.Errorf("matchPattern(%q,%q) = %v, want %v", tc.pattern, tc.action, got, tc.want)
			}
		})
	}
}

func TestRoleEvaluatorReader(t *testing.T) {
	t.Parallel()

	eval := NewRoleEvaluator(readerPerms())
	tests := []struct {
		name   string
		action Action
		want   bool
	}{
		{name: "read allowed", action: Action{Full: "Microsoft.Compute/virtualMachines/read"}, want: true},
		{
			name:   "listKeys /action denied under Reader",
			action: Action{Full: "Microsoft.Storage/storageAccounts/listKeys/action"},
			want:   false,
		},
		{
			name:   "delete denied under Reader",
			action: Action{Full: "Microsoft.Compute/virtualMachines/delete"},
			want:   false,
		},
		{
			name:   "write denied under Reader",
			action: Action{Full: "Microsoft.Compute/virtualMachines/write"},
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := eval.Allowed(tc.action); got != tc.want {
				t.Errorf("Allowed(%q) = %v, want %v", tc.action.Full, got, tc.want)
			}
		})
	}
}

func TestRoleEvaluatorNotActions(t *testing.T) {
	t.Parallel()

	// A role that grants all reads but excludes a sensitive one via NotActions.
	eval := NewRoleEvaluator(
		RolePermissions{
			Actions:    []string{"*/read"},
			NotActions: []string{"Microsoft.Web/sites/hostruntime/host/_master/read"},
		},
	)
	if eval.Allowed(Action{Full: "Microsoft.Web/sites/hostruntime/host/_master/read"}) {
		t.Error("NotActions-excluded read must be denied.")
	}
	if !eval.Allowed(Action{Full: "Microsoft.Compute/virtualMachines/read"}) {
		t.Error("ordinary read must be allowed.")
	}
}

func TestFetchRolePermissions(t *testing.T) {
	t.Parallel()

	rc := &roleClientMock{
		RolePermissionsFunc: func(_ context.Context, role string) (RolePermissions, error) {
			if role == "Reader" {
				return RolePermissions{Actions: []string{"*/read"}}, nil
			}
			return RolePermissions{}, errors.New("unknown role")
		},
	}
	perms, err := FetchRolePermissions(context.Background(), rc, "Reader")
	if err != nil {
		t.Fatalf("FetchRolePermissions: %v", err)
	}
	if len(perms.Actions) != 1 || perms.Actions[0] != "*/read" {
		t.Fatalf("Actions = %v, want [*/read]", perms.Actions)
	}
}

func TestFetchRolePermissionsFailClosed(t *testing.T) {
	t.Parallel()

	rc := &roleClientMock{
		RolePermissionsFunc: func(context.Context, string) (RolePermissions, error) {
			return RolePermissions{}, errors.New("403")
		},
	}
	if _, err := FetchRolePermissions(context.Background(), rc, "Reader"); !errors.Is(err, ErrRoleFetchFailed) {
		t.Fatalf("want ErrRoleFetchFailed, got %v", err)
	}
}
