package gcp

import (
	"testing"

	iamv1 "google.golang.org/api/iam/v1"
)

func TestPermissionNames(t *testing.T) {
	t.Parallel()

	if got := permissionNames(nil); len(got) != 0 {
		t.Errorf("permissionNames(nil) = %v, want empty", got)
	}

	got := permissionNames([]*iamv1.Permission{ //nolint:exhaustruct // only Name matters
		{Name: "compute.instances.list"},
		{Name: "compute.instances.get"},
	})
	want := []string{"compute.instances.list", "compute.instances.get"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("permissionNames = %v, want %v", got, want)
	}
}
