package azure

import (
	"fmt"
	"strings"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// ParsedHost is the structured candidate result of ParseHost. Cloud is empty on
// return from ParseHost and is filled by Catalog.ResolveCloud (Layer-3 host pin).
type ParsedHost struct {
	Host  string // normalized ARM control-plane host (e.g. "management.azure.com").
	Cloud string // filled by catalog.ResolveCloud ("AzureCloud"/"AzureUSGovernment"/"AzureChinaCloud").
}

// WithCloud returns a copy of p with Cloud replaced (used after the catalog pins
// the host to a cloud's resourceManager value).
func (p ParsedHost) WithCloud(cloud string) ParsedHost {
	p.Cloud = cloud
	return p
}

// dataPlaneSuffixes are the host suffixes whose service is encoded in the host
// (data-plane). Cynative is control-plane only: data-plane operations are out of
// scope and fail closed here. The role evaluator models only control-plane
// Actions/NotActions (see RolePermissions).
var dataPlaneSuffixes = []string{ //nolint:gochecknoglobals // immutable lookup table
	".vault.azure.net",
	".managedhsm.azure.net",
	".core.windows.net", // blob/queue/table/file
	".database.windows.net",
	".documents.azure.com",
	".servicebus.windows.net",
	".azurecr.io",
}

// graphHost is Microsoft Graph; authorized by Entra scopes, not Azure RBAC, so
// it is always out of scope and fails closed.
const graphHost = "graph.microsoft.com"

// ParseHost normalizes and structurally classifies host, returning a candidate
// control-plane ParsedHost or a sentinel (ErrHostPattern / ErrDataPlaneNotSupported
// / ErrGraphNotSupported). Pure: no I/O, no ctx. Cloud resolution is a separate
// composition step (Catalog.ResolveCloud).
func ParseHost(host string) (ParsedHost, error) {
	if host == "" {
		return ParsedHost{}, fmt.Errorf("%w: host is empty", ErrHostPattern)
	}
	norm, err := normalizeHost(host)
	if err != nil {
		return ParsedHost{}, err
	}
	if rejectHost(norm) {
		return ParsedHost{}, fmt.Errorf("%w: %q (SSRF/private/metadata/privatelink host)", ErrHostPattern, norm)
	}
	return classifyHost(norm)
}

// normalizeHost delegates to cloudauth.NormalizeHost (lowercase, userinfo reject,
// port strip, trailing-dot trim, non-ASCII reject, idna idempotency, IP-literal
// reject) and maps its ErrInvalidHost onto this package's ErrHostPattern so the
// existing error contract is preserved.
func normalizeHost(host string) (string, error) {
	norm, err := cloudauth.NormalizeHost(host)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrHostPattern, err)
	}
	return norm, nil
}

// rejectHost reports whether host is an SSRF target, a private-endpoint zone, or
// the IMDS/metadata server, which must be denied before any classification.
func rejectHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return true
	}
	if cloudauth.IsIPLiteral(host) {
		return true
	}
	// IMDS + any metadata.* host (covers metadata.azure.com / .google.internal / etc).
	if host == "metadata" || strings.HasPrefix(host, "metadata.") {
		return true
	}
	// Private-endpoint zones — reject by the .privatelink. label (resolvability-
	// independent), including a leading "privatelink." label.
	if strings.Contains(host, ".privatelink.") || strings.HasPrefix(host, "privatelink.") {
		return true
	}
	return false
}

// classifyHost maps a normalized, non-rejected host to a control-plane candidate
// or a fail-closed sentinel. Precondition: host normalized + not rejected.
func classifyHost(host string) (ParsedHost, error) {
	if host == graphHost {
		return ParsedHost{}, fmt.Errorf("%w: %q", ErrGraphNotSupported, host)
	}
	for _, suffix := range dataPlaneSuffixes {
		if strings.HasSuffix(host, suffix) {
			return ParsedHost{}, fmt.Errorf(
				"%w: data-plane host %q is out of scope (control-plane only)",
				ErrDataPlaneNotSupported,
				host,
			)
		}
	}
	if isARMControlPlaneHost(host) {
		// Candidate; the catalog pins it to a specific cloud's resourceManager.
		return ParsedHost{Host: host}, nil
	}
	return ParsedHost{}, fmt.Errorf("%w: %q", ErrHostPattern, host)
}

// armControlPlaneHosts are the known ARM resourceManager hosts across the
// data-driven clouds (public/US-Gov/China; Azure Germany is closed). The catalog
// is authoritative for cloud assignment; this set is the cheap structural gate so
// ParseHost stays pure (no I/O) and only plausible ARM hosts reach the catalog.
var armControlPlaneHosts = map[string]struct{}{ //nolint:gochecknoglobals // immutable lookup table
	"management.azure.com":         {},
	"management.usgovcloudapi.net": {},
	"management.chinacloudapi.cn":  {},
}

func isARMControlPlaneHost(host string) bool {
	_, ok := armControlPlaneHosts[host]
	return ok
}

// Verify enforces that p is consistent with the cloud the model declared via
// azure_auth.Cloud. The service is verified at Layer 2 against the URL path, not
// here. Pure: no I/O. An empty claim accepts; a non-empty claim requires a
// resolved, matching cloud. Both sides are canonicalized first.
func Verify(p ParsedHost, claimedCloud string) error {
	claim := canonicalizeCloudName(claimedCloud)
	if claim == "" {
		return nil // cloud derived from the host; nothing to cross-check.
	}
	resolved := canonicalizeCloudName(p.Cloud)
	if resolved == "" {
		return fmt.Errorf("%w: cloud claim %q but host %q is not pinned to a cloud",
			ErrHostClaimMismatch, claimedCloud, p.Host)
	}
	if !strings.EqualFold(resolved, claim) {
		return fmt.Errorf("%w: host implies cloud %q but azure_auth.cloud is %q",
			ErrHostClaimMismatch, p.Cloud, claimedCloud)
	}
	return nil
}
