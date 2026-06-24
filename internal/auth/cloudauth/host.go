// Package cloudauth holds auth primitives shared by the aws/gcp/azure auth
// subpackages: a host normalizer and small HTTP/string shell helpers. It imports
// nothing from the parent auth package, so the subpackages may depend on it
// without an import cycle.
package cloudauth

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// maxASCII is the highest pure-ASCII Unicode code point (U+007F). Any rune above
// this value cannot appear in a normalized cloud-API hostname; rejecting them
// outright eliminates the IDNA fullwidth-digit / homoglyph smuggle surface for
// an all-ASCII allowlist.
const maxASCII = 0x7f

// ErrInvalidHost is returned by NormalizeHost when the host is empty, carries
// userinfo, contains a non-ASCII rune, fails IDNA idempotency, or is an IP
// literal. Callers may wrap it or map it to their own sentinel.
var ErrInvalidHost = errors.New("cloudauth: invalid host")

// NormalizeHost lower-cases and trims the host, rejects userinfo, rejects a bare
// (unbracketed) IPv6 literal — which has two or more colons, unlike a host:port
// that has exactly one — strips a single :port, trims a single trailing dot,
// rejects any non-ASCII rune, enforces idna.Lookup.ToASCII idempotency, and
// finally rejects any host that parses as an IP literal. Bracketed IPv6 literals
// keep their brackets so the idna check rejects them. It does NOT reject
// localhost or any specific domain — that policy stays in each cloud's
// rejectHost. Pure: no I/O.
func NormalizeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", fmt.Errorf("%w: host is empty", ErrInvalidHost)
	}
	if strings.Contains(host, "@") {
		return "", fmt.Errorf("%w: %q (userinfo not allowed)", ErrInvalidHost, host)
	}
	if !strings.HasPrefix(host, "[") {
		// A host:port has exactly one colon; two or more means a bare IPv6 literal.
		if strings.Count(host, ":") > 1 {
			return "", fmt.Errorf("%w: %q (bare IPv6 literal)", ErrInvalidHost, host)
		}
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h // strip the single :port.
		}
	}
	host = strings.TrimSuffix(host, ".")
	for _, r := range host {
		if r > maxASCII {
			return "", fmt.Errorf("%w: %q (non-ASCII / IDN host)", ErrInvalidHost, host)
		}
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii != host {
		return "", fmt.Errorf("%w: %q (IDN normalization mismatch)", ErrInvalidHost, host)
	}
	if _, perr := netip.ParseAddr(host); perr == nil {
		return "", fmt.Errorf("%w: %q (IP literal)", ErrInvalidHost, host)
	}
	return host, nil
}

// IsIPLiteral reports whether host is an IP literal: a bracketed form ("[...]"),
// any bare-colon IPv6 (including IPv4-mapped like "::ffff:169.254.169.254"), or
// a string [netip.ParseAddr] accepts. It returns false for non-canonical numeric
// forms (DWORD/octal/hex) that netip rejects — those are blocked by each cloud's
// suffix allowlist, not here. Pure: no I/O.
func IsIPLiteral(host string) bool {
	if strings.HasPrefix(host, "[") {
		return true
	}
	if strings.Contains(host, ":") {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

// HostOf extracts the lowercase host component from a raw URL string without
// importing net/url, trimming a single trailing dot. It is the shared host
// extractor for the cloudauth, gcp, and azure host→service indices. Pure: no I/O.
func HostOf(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	h, _, _ := strings.Cut(s, "/")
	return strings.TrimSuffix(strings.ToLower(h), ".")
}
