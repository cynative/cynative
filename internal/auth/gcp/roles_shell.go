package gcp

import (
	"context"
	"fmt"
	"net/http"

	iamv1 "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// IAMClientConfig configures the real IAM-backed roles/permissions client. Roles
// are fetched live per resolve (GetRole) — not cached — matching the Azure role
// definition and AWS IAM policy document.
type IAMClientConfig struct {
	Endpoint   string // test override; "" uses the default googleapis endpoint.
	HTTPClient *http.Client
}

// IAMRolesClient is the public interface returned by NewIAMRolesClient. It
// exposes both role definition fetch and testable-permissions enumeration.
// It intentionally mirrors iamRolesClient to provide a stable public surface.
//
//nolint:iface // public surface mirrors private iamRolesClient intentionally.
type IAMRolesClient interface {
	iamRolesClient
}

type iamClient struct {
	svc *iamv1.Service
}

// NewIAMRolesClient builds the real IAM client. Excluded from the coverage gate.
func NewIAMRolesClient(ctx context.Context, cfg IAMClientConfig) (IAMRolesClient, error) {
	opts := []option.ClientOption{}
	if cfg.HTTPClient != nil {
		opts = append(opts, option.WithHTTPClient(cfg.HTTPClient))
	}
	if cfg.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(cfg.Endpoint))
	}
	svc, err := defaultGCPNewIAMService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("build iam service: %w", err)
	}
	return &iamClient{svc: svc}, nil
}

// defaultGCPNewIAMService is the func-field-style seam for the real client.
func defaultGCPNewIAMService(ctx context.Context, opts ...option.ClientOption) (*iamv1.Service, error) {
	return iamv1.NewService(ctx, opts...)
}

// GetRole returns the role definition for the named role, dispatching by ref
// kind to the predefined / project-custom / org-custom IAM endpoint. Implements
// iamRolesClient.
func (c *iamClient) GetRole(ctx context.Context, roleName string) (RoleDefinition, error) {
	kind, err := ParseRoleReference(roleName)
	if err != nil {
		return RoleDefinition{}, err
	}
	var role *iamv1.Role
	switch kind {
	case RoleRefPredefined:
		role, err = c.svc.Roles.Get(roleName).Context(ctx).Do()
	case RoleRefProjectCustom:
		role, err = c.svc.Projects.Roles.Get(roleName).Context(ctx).Do()
	case RoleRefOrgCustom:
		role, err = c.svc.Organizations.Roles.Get(roleName).Context(ctx).Do()
	default:
		return RoleDefinition{}, fmt.Errorf("%w: %q", ErrInvalidRoleRef, roleName)
	}
	if err != nil {
		return RoleDefinition{}, fmt.Errorf("roles.get %q: %w", roleName, err)
	}
	return RoleDefinition{
		IncludedPermissions: role.IncludedPermissions,
		Stage:               role.Stage,
		Deleted:             role.Deleted,
	}, nil
}

// maxTestablePermissionsPageSize is the API maximum for
// queryTestablePermissions (default 100). Requesting the max minimises the
// number of sequential round trips through the project's full permission set,
// keeping the one-time bootstrap well inside its budget (#241).
const maxTestablePermissionsPageSize = 1000

// QueryTestablePermissions pages through queryTestablePermissions for
// fullResourceName and returns the union of all permission names.
func (c *iamClient) QueryTestablePermissions(ctx context.Context, fullResourceName string) ([]string, error) {
	var all []string
	pageToken := ""
	for {
		resp, err := c.svc.Permissions.QueryTestablePermissions(&iamv1.QueryTestablePermissionsRequest{
			FullResourceName: fullResourceName,
			PageSize:         maxTestablePermissionsPageSize,
			PageToken:        pageToken,
		}).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("queryTestablePermissions: %w", err)
		}
		all = append(all, permissionNames(resp.Permissions)...)
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return all, nil
}
