package gcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
)

func TestRolesShellGetRoleAndTestablePermissions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/roles/viewer", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(
			[]byte(`{"name":"roles/viewer","includedPermissions":["compute.instances.list","storage.buckets.list"]}`),
		)
	})
	page := 0
	mux.HandleFunc("/v1/permissions:queryTestablePermissions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PageSize int `json:"pageSize"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.PageSize != 1000 {
			t.Errorf("queryTestablePermissions pageSize = %d, want 1000 (fewer round trips)", body.PageSize)
		}
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{"permissions":[{"name":"compute.instances.list"}],"nextPageToken":"p2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"permissions":[{"name":"storage.buckets.list"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := gcphardening.NewIAMRolesClient(context.Background(), gcphardening.IAMClientConfig{
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewIAMRolesClient: %v", err)
	}

	def, err := client.GetRole(context.Background(), "roles/viewer")
	if err != nil || len(def.IncludedPermissions) != 2 {
		t.Fatalf("GetRole = %+v err=%v", def, err)
	}
	all, err := client.QueryTestablePermissions(
		context.Background(),
		"//cloudresourcemanager.googleapis.com/projects/p",
	)
	if err != nil || len(all) != 2 {
		t.Fatalf("QueryTestablePermissions = %v err=%v (paginated)", all, err)
	}
}

func TestRolesShellGetRoleDispatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/roles/viewer", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"roles/viewer","includedPermissions":["compute.instances.list"],"stage":"GA"}`))
	})
	mux.HandleFunc("/v1/projects/p/roles/customViewer", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(
			[]byte(`{"name":"projects/p/roles/customViewer","includedPermissions":["storage.buckets.list"]}`),
		)
	})
	mux.HandleFunc("/v1/organizations/o/roles/orgViewer", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(
			[]byte(
				`{"name":"organizations/o/roles/orgViewer","includedPermissions":["resourcemanager.projects.get"],"stage":"BETA"}`,
			),
		)
	})
	mux.HandleFunc("/v1/projects/p/roles/disabledRole", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(
			[]byte(
				`{"name":"projects/p/roles/disabledRole","includedPermissions":["storage.buckets.list"],"stage":"DISABLED"}`,
			),
		)
	})
	mux.HandleFunc("/v1/projects/p/roles/deletedRole", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(
			[]byte(
				`{"name":"projects/p/roles/deletedRole","includedPermissions":["storage.buckets.list"],"deleted":true}`,
			),
		)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := gcphardening.NewIAMRolesClient(context.Background(), gcphardening.IAMClientConfig{
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewIAMRolesClient: %v", err)
	}

	cases := []struct {
		role    string
		perm    string
		stage   string
		deleted bool
	}{
		{"roles/viewer", "compute.instances.list", "GA", false},
		{"projects/p/roles/customViewer", "storage.buckets.list", "", false},
		{"organizations/o/roles/orgViewer", "resourcemanager.projects.get", "BETA", false},
		{"projects/p/roles/disabledRole", "storage.buckets.list", "DISABLED", false},
		{"projects/p/roles/deletedRole", "storage.buckets.list", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.role, func(t *testing.T) {
			def, getErr := client.GetRole(context.Background(), tc.role)
			if getErr != nil {
				t.Fatalf("GetRole(%q): %v (wrong endpoint dispatched?)", tc.role, getErr)
			}
			if len(def.IncludedPermissions) != 1 || def.IncludedPermissions[0] != tc.perm {
				t.Errorf("GetRole(%q) perms = %v, want [%s]", tc.role, def.IncludedPermissions, tc.perm)
			}
			if def.Stage != tc.stage || def.Deleted != tc.deleted {
				t.Errorf("GetRole(%q) stage=%q deleted=%t, want stage=%q deleted=%t",
					tc.role, def.Stage, def.Deleted, tc.stage, tc.deleted)
			}
		})
	}
}
