package azure

import (
	"context"
	"errors"
	"testing"
)

// identityProberFunc is a func-to-interface adapter for identityProber.
type identityProberFunc func(ctx context.Context) (Identity, error)

func (f identityProberFunc) Probe(ctx context.Context) (Identity, error) { return f(ctx) }

func happyLazyDeps(t *testing.T) LazyDeps {
	t.Helper()
	const home = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	return LazyDeps{
		RoleDefinition: "Reader",
		Catalog:        fakeCatalog(t), // from the catalog test helpers.
		Roles: &roleClientMock{
			RolePermissionsFunc: func(context.Context, string) (RolePermissions, error) {
				return RolePermissions{Actions: []string{"*/read"}}, nil
			},
		},
		Identity: identityProberFunc(func(context.Context) (Identity, error) {
			return Identity{Principal: "me@contoso.onmicrosoft.com", TenantID: home}, nil
		}),
	}
}

func TestLazyResolveHappy(t *testing.T) {
	t.Parallel()
	res, err := LazyResolve(context.Background(), happyLazyDeps(t))
	if err != nil {
		t.Fatalf("LazyResolve: %v", err)
	}
	if res.ActionProvider == nil {
		t.Fatal("ActionProvider nil")
	}
}

func TestLazyResolveNotReady(t *testing.T) {
	t.Parallel()

	t.Run("identity failure", func(t *testing.T) {
		t.Parallel()
		cause := errors.New("AADSTS 401")
		deps := happyLazyDeps(t)
		deps.Identity = identityProberFunc(func(context.Context) (Identity, error) {
			return Identity{}, cause
		})
		_, err := LazyResolve(context.Background(), deps)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, cause) {
			t.Errorf("err = %v, want to wrap %v", err, cause)
		}
	})

	t.Run("role fetch failure", func(t *testing.T) {
		t.Parallel()
		cause := errors.New("roleDefinitions 403")
		deps := happyLazyDeps(t)
		deps.Roles = &roleClientMock{
			RolePermissionsFunc: func(context.Context, string) (RolePermissions, error) {
				return RolePermissions{}, cause
			},
		}
		_, err := LazyResolve(context.Background(), deps)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, cause) {
			t.Errorf("err = %v, want to wrap %v", err, cause)
		}
	})
}
