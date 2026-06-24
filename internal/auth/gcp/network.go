package gcp

import (
	"fmt"
	"strings"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// wwwCompoundSentinel marks a host that resolves its service from the request
// PATH (the ~7 www.googleapis.com compound APIs) rather than from the host. The
// composition step (Catalog.ResolveService) replaces it via WithService. It is
// non-empty so ParseHost never returns an accidentally-empty Service on success.
const wwwCompoundSentinel = "\x00www-compound"

// wwwGoogleapisHost is the literal hostname for the www.googleapis.com compound
// endpoint (used in host gating and sentinel dispatch).
const wwwGoogleapisHost = "www.googleapis.com"

// WWWCompoundSentinel returns the sentinel value used by ParseHost when the host
// is www.googleapis.com. Callers outside this package use this to detect the
// compound-API case without importing an internal constant.
func WWWCompoundSentinel() string { return wwwCompoundSentinel }

// ParsedHost is the structured candidate result of ParseHost.
type ParsedHost struct {
	Service  string // resolved canonical Discovery service short name (e.g. "compute", "storage").
	Location string // empty for global services.
}

// WithService returns a copy of p with Service replaced (used to fill the
// www-compound sentinel after path-based resolution).
func (p ParsedHost) WithService(svc string) ParsedHost {
	p.Service = svc
	return p
}

const googleapisSuffix = ".googleapis.com"

// storageService is the canonical Discovery short name for Cloud Storage, used
// in the bucket-subdomain host dispatch (e.g. bucket.storage.googleapis.com).
const storageService = "storage"

// ParseHost normalizes and structurally classifies host, returning a candidate
// ParsedHost or ErrHostPattern. Pure: no I/O, no ctx.
func ParseHost(host string) (ParsedHost, error) {
	if host == "" {
		return ParsedHost{}, fmt.Errorf("%w: host is empty", ErrHostPattern)
	}
	norm, err := normalizeHost(host)
	if err != nil {
		return ParsedHost{}, err
	}
	if rejectHost(norm) {
		return ParsedHost{}, fmt.Errorf("%w: %q (SSRF/PSC/private/non-googleapis host)", ErrHostPattern, norm)
	}
	return dispatchHost(norm)
}

// normalizeHost delegates to cloudauth.NormalizeHost (lowercase, userinfo
// reject, port strip, trailing-dot trim, non-ASCII reject, idna idempotency,
// IP-literal reject) and maps its ErrInvalidHost onto this package's
// ErrHostPattern so the existing error contract is preserved.
func normalizeHost(host string) (string, error) {
	norm, err := cloudauth.NormalizeHost(host)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrHostPattern, err)
	}
	return norm, nil
}

// rejectHost reports whether host is an SSRF target, a PSC/private VIP, or a
// non-googleapis data-plane host that must be denied before any accept.
func rejectHost(host string) bool {
	if host == "localhost" || host == "metadata.google.internal" {
		return true
	}
	if cloudauth.IsIPLiteral(host) {
		return true
	}
	if host == "private.googleapis.com" || host == "restricted.googleapis.com" {
		return true
	}
	if strings.HasSuffix(host, ".p.rep.googleapis.com") {
		return true // PSC endpoint — host does not identify the service.
	}
	for _, dataPlane := range []string{".run.app", ".appspot.com", ".cloudfunctions.net", ".pkg.dev", ".gcr.io"} {
		if strings.HasSuffix(host, dataPlane) {
			return true
		}
	}
	// Anything not under .googleapis.com (and not www.googleapis.com) is out.
	if host != wwwGoogleapisHost && !strings.HasSuffix(host, googleapisSuffix) {
		return true
	}
	return false
}

// dispatchHost resolves the candidate (service, location) by suffix dispatch in
// priority order. Precondition: host normalized + not rejected.
func dispatchHost(host string) (ParsedHost, error) {
	if host == wwwGoogleapisHost {
		// Service resolved from the request PATH at composition time.
		return ParsedHost{Service: wwwCompoundSentinel}, nil
	}
	body := strings.TrimSuffix(host, googleapisSuffix)
	if body == host || body == "" {
		return ParsedHost{}, fmt.Errorf("%w: %q", ErrHostPattern, host)
	}

	// <svc>.mtls
	if svc, ok := strings.CutSuffix(body, ".mtls"); ok && svc != "" && !strings.Contains(svc, ".") {
		return ParsedHost{Service: svc}, nil
	}
	// <svc>.<location>.rep  (newer regional)
	if rest, ok := strings.CutSuffix(body, ".rep"); ok {
		svc, loc, found := strings.Cut(rest, ".")
		if found && svc != "" && loc != "" && !strings.Contains(loc, ".") {
			return ParsedHost{Service: svc, Location: loc}, nil
		}
		return ParsedHost{}, fmt.Errorf("%w: %q (malformed rep host)", ErrHostPattern, host)
	}
	// <bucket>.storage  → service storage (bucket label opaque)
	if strings.HasSuffix(body, "."+storageService) || body == storageService {
		return ParsedHost{Service: storageService}, nil
	}
	// <location>-<svc>  (legacy locational: location may contain hyphens, service
	// is the final hyphen-delimited token and must be a single label).
	// Plain <svc>.googleapis.com has no hyphen at all — that falls through to the
	// single-label branch below.
	if idx := strings.LastIndex(body, "-"); idx > 0 {
		svc := body[idx+1:]
		loc := body[:idx]
		if svc != "" && !strings.Contains(svc, ".") && !strings.Contains(loc, ".") {
			return ParsedHost{Service: svc, Location: loc}, nil
		}
	}
	if !strings.Contains(body, ".") {
		return ParsedHost{Service: body}, nil // plain <svc>.googleapis.com
	}
	return ParsedHost{}, fmt.Errorf("%w: %q", ErrHostPattern, host)
}

// Verify enforces that p is consistent with the (service, location) the model
// declared via gcp_auth. Pure: no I/O.
func Verify(p ParsedHost, claimedService, claimedLocation string) error {
	if p.Service == "" || claimedService == "" {
		return fmt.Errorf("%w: empty service", ErrHostClaimMismatch)
	}
	if !strings.EqualFold(p.Service, claimedService) {
		return fmt.Errorf("%w: host implies service %q but gcp_auth.service is %q",
			ErrHostClaimMismatch, p.Service, claimedService)
	}
	if claimedLocation == "" {
		return nil // location derived from the pinned host; nothing to cross-check.
	}
	if p.Location == "" {
		switch strings.ToLower(claimedLocation) {
		case "", "global":
			return nil
		default:
			return fmt.Errorf("%w: global service %q got non-global location %q",
				ErrHostClaimMismatch, p.Service, claimedLocation)
		}
	}
	if !strings.EqualFold(p.Location, claimedLocation) {
		return fmt.Errorf("%w: host implies location %q but gcp_auth.location is %q",
			ErrHostClaimMismatch, p.Location, claimedLocation)
	}
	return nil
}
