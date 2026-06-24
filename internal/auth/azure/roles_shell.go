package azure

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

// RoleClientConfig configures the real ARM-backed role client. The role
// definition is listed live per resolve (not cached) — matching AWS's IAM policy
// document and GCP's GetRole.
type RoleClientConfig struct {
	Endpoint   string                 // test override; "" uses the cloud's ARM host.
	HTTPClient *http.Client           // test override.
	Credential azcore.TokenCredential // home-tenant ARM credential; nil → NewCredentialChain.
	Cloud      CloudConfig            // resolved cloud; its ARM endpoint/audience + AAD authority target the role-defs client.
}

// roleDefinitionsClient is the armauthorization subset the shell needs: list (to
// resolve roleName → definition). Mirrored locally so the seam is moq-free here
// (gated tests hit roleClient via the moq in roleeval.go).
type roleDefinitionsClient interface {
	NewListPager(scope string, opts *armauthorization.RoleDefinitionsClientListOptions) listPager
}

// listPager is the pager returned by roleDefinitionsClient.NewListPager.
type listPager interface {
	More() bool
	NextPage(ctx context.Context) (armauthorization.RoleDefinitionsClientListResponse, error)
}

type roleClientImpl struct {
	defs  roleDefinitionsClient
	scope string
}

// NewRoleClient builds the real role client. Excluded from the coverage gate.
func NewRoleClient(cfg RoleClientConfig) (roleClient, error) {
	cred := cfg.Credential
	if cred == nil {
		cc := cfg.Cloud
		if cc.Name == "" {
			cc = ResolveCloudConfig(CloudPublic, "", nil)
		}
		dc, err := NewCredentialChain(cc)
		if err != nil {
			return nil, fmt.Errorf("default credential: %w", err)
		}
		cred = dc
	}
	defs, err := defaultAzureNewRoleDefinitionsClient(cred, cfg)
	if err != nil {
		return nil, fmt.Errorf("role definitions client: %w", err)
	}
	return &roleClientImpl{defs: defs, scope: "/"}, nil
}

// defaultAzureNewRoleDefinitionsClient is the func-variable seam wrapping the
// raw armauthorization constructor. Excluded from the coverage gate.
//
//nolint:gochecknoglobals // injectable shell seam, excluded from the gate.
var defaultAzureNewRoleDefinitionsClient = func(
	cred azcore.TokenCredential, cfg RoleClientConfig,
) (roleDefinitionsClient, error) {
	opts := &arm.ClientOptions{} //nolint:exhaustruct // defaults fine; overrides below.
	switch {
	case cfg.Endpoint != "":
		opts.ClientOptions.Cloud.Services = map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: cfg.Endpoint, Audience: cfg.Endpoint},
		}
		// Allow HTTP for test servers (httptest.NewServer is plain HTTP).
		if !strings.HasPrefix(cfg.Endpoint, "https://") {
			opts.InsecureAllowCredentialWithHTTP = true
		}
	case cfg.Cloud.Name != "":
		// Production: target the resolved cloud's ARM endpoint/audience + AAD authority.
		opts.ClientOptions.Cloud = ToSDKCloud(cfg.Cloud)
	}
	if cfg.HTTPClient != nil {
		opts.ClientOptions.Transport = cfg.HTTPClient
	}
	c, err := armauthorization.NewRoleDefinitionsClient(cred, opts)
	if err != nil {
		return nil, err
	}
	return roleDefsAdapter{c: c}, nil
}

type roleDefsAdapter struct {
	c *armauthorization.RoleDefinitionsClient
}

func (a roleDefsAdapter) NewListPager(
	scope string, opts *armauthorization.RoleDefinitionsClientListOptions,
) listPager {
	return a.c.NewListPager(scope, opts)
}

// RolePermissions resolves roleNameOrID to its static permission set. A bare GUID
// is matched against the definition name; otherwise it is matched against
// properties.roleName (case-insensitive). Implements roleClient.
func (c *roleClientImpl) RolePermissions(ctx context.Context, roleNameOrID string) (RolePermissions, error) {
	pager := c.defs.NewListPager(c.scope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return RolePermissions{}, fmt.Errorf("roleDefinitions list: %w", err)
		}
		if perms, ok := selectRolePermissions(page.Value, roleNameOrID); ok {
			return perms, nil
		}
	}
	return RolePermissions{}, fmt.Errorf("role %q not found", roleNameOrID)
}
