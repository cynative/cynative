package auth

import (
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// httpsPort is the port an https URL addresses when it names none.
const httpsPort = "443"

// defaultedPort returns port, or the https default when empty. The view reports
// an absent port as "", and [net/http] normalizes an explicit-but-empty port to
// the same thing before any gate runs, so "" here means "no port given".
func defaultedPort(port string) string {
	if port == "" {
		return httpsPort
	}

	return port
}

// authorizeRequestPort denies a request whose port is not the one the
// connector is pinned to. The host gates receive a port-stripped hostname (the
// transport passes the view's Hostname) and the dial guard sees only an IP, so
// this is the only place the port is bound: without it a model can reach a
// different TLS listener on the pinned host or IP and have the injected
// credential attached there. want is the connector's own port, already
// defaulted; an empty want denies, so a connector that never configured one
// cannot silently inherit 443.
func authorizeRequestPort(v authreq.View, want string) error {
	if want == "" {
		return fmt.Errorf("%w: no endpoint port is configured for this connector", ErrHostNotAuthorized)
	}

	if got := defaultedPort(v.Port); got != want {
		return fmt.Errorf(
			"%w: %s serves port %s, not the requested port %s",
			ErrHostNotAuthorized,
			v.Hostname,
			want,
			got,
		)
	}

	return nil
}

// ErrNonASCIIHost is returned for a host carrying a byte outside ASCII. Such a
// name has more than one spelling and the spellings do not agree: Go's case
// mapping, the IDNA conversion the HTTP client applies before it dials, and the
// conversion it applies to the Host header are three different transforms. A
// gate would authorize one of those spellings and the wire would reach another.
// Punycode is ASCII and is unaffected. Same class as #243 and #247.
var ErrNonASCIIHost = errors.New("host is not ASCII")

// ErrZonedHost is returned for a host that is an IP literal carrying a zone
// identifier, as in "fe80::1%eth0". A zone names a local interface, and Go
// resolves it to a number before the connect: zoneCache.index in
// net/interface.go looks the zone up in a map keyed by interface name, a
// case-sensitive lookup, and falls back to reading the zone as a decimal
// index when that misses. The number it returns is the ZoneId of the
// SockaddrInet6 (net/ipsock_posix.go). So a numeric zone works too, and a
// name in the wrong case resolves to a different index than the same name
// spelled right. That makes the zone the one part of an ASCII authority that
// is case-sensitive: the gates classify a lower-cased hostname while the dial
// resolves the spelling the caller wrote, so "%ETH0" would be authorized as
// "%eth0" and dialed on whatever index "%ETH0" resolves to.
// Admitting ASCII case as a difference that changes nothing is what the rest
// of this rule rests on, and the zone is where that stops being true.
var ErrZonedHost = errors.New("host carries an IP zone identifier")

// AdmitHost is the one admission rule behind the authority invariant: it
// admits a host only when that host has a single spelling this system can both
// authorize and send. It turns away two shapes, each under its own sentinel,
// and its guarantee is narrow. An admitted host survives lower-casing as the
// same name the client resolves and sends, which does not make every wire
// transform an identity.
//
// ErrNonASCIIHost covers a byte of 0x80 or above. That removes the Unicode
// case-folding and the IDNA ambiguity, the transforms that can turn one
// written name into two different resolved ones. The scan is over bytes rather
// than runes and the two reject the same strings, in both directions: a rune
// above U+007F encodes as bytes that are each 0x80 or above, so every string a
// rune scan rejects has such a byte; and no byte of 0x80 or above belongs to a
// rune at or below U+007F, so every string a byte scan rejects holds either a
// rune above U+007F or a malformed sequence. The byte scan needs no U+FFFD
// substitution to reject the malformed case, which a range loop would rely on.
//
// ErrZonedHost covers an IP literal with a zone. Go's resolver treats a host
// as a zoned literal exactly when [netip.ParseAddr] parses it with a non-empty
// zone (net.Resolver.lookupIPAddr), so that is the test here and not a search
// for "%". The two differ: a percent also reaches a hostname as an escape that
// survived parsing, as in the host of "https://api.%25.com/x", which names no
// interface and has no case-sensitive part for this rule to turn away.
//
// The order of the two only decides the diagnostic: a zone holding a non-ASCII
// byte is reported as non-ASCII, which it also is. Pure: no I/O.
func AdmitHost(host string) error {
	for i := range len(host) {
		if host[i] >= utf8.RuneSelf {
			return fmt.Errorf("%w: %q; write an internationalized name in punycode", ErrNonASCIIHost, host)
		}
	}

	if addr, err := netip.ParseAddr(host); err == nil && addr.Zone() != "" {
		return fmt.Errorf("%w: %q; address the host without a zone suffix", ErrZonedHost, host)
	}

	return nil
}
