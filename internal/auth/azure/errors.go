// Package azure implements Azure-specific hardening that layers on top of the
// generic auth.Provider contract. Unlike AWS/GCP there is no credential-
// downscoping primitive, so client-side action authorization (Layer 2) and host
// pinning (Layer 3) carry the full enforcement weight.
package azure

import "errors"

var (
	ErrHostPattern        = errors.New("azure_hardening: unrecognized host pattern")
	ErrHostClaimMismatch  = errors.New("azure_hardening: host does not match azure_auth claim")
	ErrCatalogUnavailable = errors.New("azure_hardening: endpoint/provider-operations catalog unavailable")
	ErrActionUnresolved   = errors.New("azure_hardening: cannot resolve required RBAC action")
	ErrActionAmbiguous    = errors.New(
		"azure_hardening: ambiguous action (catalog has read and action for one path)",
	)
	ErrActionDenied          = errors.New("azure_hardening: action not allowed by role definition")
	ErrDataPlaneNotSupported = errors.New("azure_hardening: data-plane operations out of scope (control-plane only)")
	ErrGraphNotSupported     = errors.New("azure_hardening: Microsoft Graph is not Azure-RBAC-gated")
	// ErrTenantUnresolved covers caller identity/token-resolution failures (a
	// malformed/undecodable ARM token), not cross-tenant denial.
	ErrTenantUnresolved        = errors.New("azure_hardening: target tenant could not be resolved")
	ErrRoleFetchFailed         = errors.New("azure_hardening: role definition fetch failed")
	ErrModelSuppliedCredential = errors.New("azure_hardening: model-supplied credential (SAS) rejected")
)
