package gcp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

// identityProberFunc is a func-to-interface adapter for identityProber.
type identityProberFunc func(ctx context.Context) (principal, projectID string, err error)

func (f identityProberFunc) Probe(ctx context.Context) (string, string, error) { return f(ctx) }

// fakeTS is a fake oauth2.TokenSource.
type fakeTS struct {
	tok  *oauth2.Token
	err  error
	hits atomic.Int32
}

func (f *fakeTS) Token() (*oauth2.Token, error) {
	f.hits.Add(1)

	return f.tok, f.err
}

func happyDeps(t *testing.T) LazyDeps {
	t.Helper()
	cat := fakeCatalog(t)
	cat.injectMethods("compute", computeIndex())
	return LazyDeps{
		Role:    "roles/viewer",
		Catalog: cat,
		Dataset: emptyDataset{},
		Roles: &iamRolesClientMock{
			GetRoleFunc: func(context.Context, string) (RoleDefinition, error) {
				return RoleDefinition{IncludedPermissions: []string{"compute.instances.list"}}, nil
			},
			QueryTestablePermissionsFunc: func(context.Context, string) ([]string, error) {
				return []string{"compute.instances.list"}, nil
			},
		},
		Identity: identityProberFunc(func(context.Context) (string, string, error) {
			return "me@example.com", "cynative", nil
		}),
		RootSource: &fakeTS{tok: &oauth2.Token{AccessToken: "raw"}}, //nolint:exhaustruct // fake: only tok matters
	}
}

func TestLazyResolveHappy(t *testing.T) {
	t.Parallel()
	res, err := LazyResolve(context.Background(), happyDeps(t))
	if err != nil {
		t.Fatalf("LazyResolve: %v", err)
	}
	if res.ActionProvider == nil || res.TokenSource == nil {
		t.Fatal("LazyResult incomplete")
	}
	// The injected token is the raw ADC source, unchanged.
	tok, _ := res.TokenSource.Token()
	if tok.AccessToken != "raw" {
		t.Errorf("token = %q, want raw", tok.AccessToken)
	}
}

func TestLazyResolveProjectUnresolved(t *testing.T) {
	t.Parallel()
	deps := happyDeps(t)
	deps.Identity = identityProberFunc(func(context.Context) (string, string, error) {
		return "me@example.com", "", nil // empty projectID → fail closed.
	})
	if _, err := LazyResolve(context.Background(), deps); !errors.Is(err, ErrProjectUnresolved) {
		t.Fatalf("err = %v, want ErrProjectUnresolved", err)
	}
}

func TestLazyResolveNotReady(t *testing.T) {
	t.Parallel()

	t.Run("identity failure", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("tokeninfo 401")
		deps := happyDeps(t)
		deps.Identity = identityProberFunc(func(context.Context) (string, string, error) {
			return "", "", sentinel
		})
		_, err := LazyResolve(context.Background(), deps)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want wrap of %v", err, sentinel)
		}
	})

	t.Run("role fetch failure", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("403")
		deps := happyDeps(t)
		deps.Roles = &iamRolesClientMock{
			GetRoleFunc: func(context.Context, string) (RoleDefinition, error) {
				return RoleDefinition{}, sentinel
			},
			QueryTestablePermissionsFunc: func(context.Context, string) ([]string, error) { return nil, nil },
		}
		_, err := LazyResolve(context.Background(), deps)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want wrap of %v", err, sentinel)
		}
	})
}

func TestLazyResolvePermissionCatalogFailure(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("queryTestablePermissions 403")
	deps := happyDeps(t)
	deps.Roles = &iamRolesClientMock{
		GetRoleFunc: func(context.Context, string) (RoleDefinition, error) {
			return RoleDefinition{IncludedPermissions: []string{"compute.instances.list"}}, nil
		},
		QueryTestablePermissionsFunc: func(context.Context, string) ([]string, error) {
			return nil, sentinel
		},
	}
	_, err := LazyResolve(context.Background(), deps)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wrap of %v", err, sentinel)
	}
}

func TestLazyResolveRoleDisabled(t *testing.T) {
	t.Parallel()
	deps := happyDeps(t)
	deps.Role = "projects/p/roles/r"
	deps.Roles = &iamRolesClientMock{
		GetRoleFunc: func(context.Context, string) (RoleDefinition, error) {
			return RoleDefinition{IncludedPermissions: []string{"compute.instances.list"}, Stage: "DISABLED"}, nil
		},
		QueryTestablePermissionsFunc: func(context.Context, string) ([]string, error) { return nil, nil },
	}
	if _, err := LazyResolve(context.Background(), deps); !errors.Is(err, ErrRoleDisabled) {
		t.Fatalf("err = %v, want ErrRoleDisabled", err)
	}
}

func TestLazyResolveTestablePermsUseCallerProject(t *testing.T) {
	t.Parallel()
	deps := happyDeps(t)
	deps.Role = "projects/role-proj/roles/r" // role lives in a different project...
	deps.Identity = identityProberFunc(func(context.Context) (string, string, error) {
		return "me@example.com", "caller-proj", nil // ...than the caller.
	})
	var gotResource string
	deps.Roles = &iamRolesClientMock{
		GetRoleFunc: func(context.Context, string) (RoleDefinition, error) {
			return RoleDefinition{IncludedPermissions: []string{"compute.instances.list"}}, nil
		},
		QueryTestablePermissionsFunc: func(_ context.Context, fullResourceName string) ([]string, error) {
			gotResource = fullResourceName
			return []string{"compute.instances.list"}, nil
		},
	}
	if _, err := LazyResolve(context.Background(), deps); err != nil {
		t.Fatalf("LazyResolve: %v", err)
	}
	if want := "//cloudresourcemanager.googleapis.com/projects/caller-proj"; gotResource != want {
		t.Errorf("testable-perms resource = %q, want %q (role scope must not leak)", gotResource, want)
	}
}
