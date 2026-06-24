package gcp

import "errors"

var (
	ErrHostPattern          = errors.New("gcp_hardening: unrecognized host pattern")
	ErrHostClaimMismatch    = errors.New("gcp_hardening: host does not match gcp_auth claim")
	ErrCatalogUnavailable   = errors.New("gcp_hardening: API discovery catalog unavailable")
	ErrClassifierUnknownOp  = errors.New("gcp_hardening: cannot identify method from request")
	ErrPermissionUnresolved = errors.New("gcp_hardening: cannot resolve required permission")
	ErrPermissionDenied     = errors.New("gcp_hardening: permission not in allow-list role(s)")
	ErrRoleFetchFailed      = errors.New("gcp_hardening: allow-list role fetch failed")
	ErrRoleDisabled         = errors.New("gcp_hardening: allow-list role is disabled or deleted")
	ErrInvalidRoleRef       = errors.New("gcp_hardening: invalid role reference")
	ErrProjectUnresolved    = errors.New("gcp_hardening: caller project ID could not be resolved")
)
