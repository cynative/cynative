package auth

import (
	"errors"
	"fmt"
	"unicode"

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

// ErrNonASCIIHost is returned for a host carrying a rune above U+007F. Such a
// name has more than one spelling and the spellings do not agree: Go's case
// mapping, the IDNA conversion the HTTP client applies before it dials, and the
// conversion it applies to the Host header are three different transforms. A
// gate would authorize one of those spellings and the wire would reach another.
// Punycode is ASCII and is unaffected. Same class as #243 and #247.
var ErrNonASCIIHost = errors.New("host is not ASCII")

// ASCIIHost rejects a host containing a rune above U+007F. It is the one
// admission rule behind the authority invariant, and its guarantee is narrow:
// it removes the Unicode case-folding and the IDNA ambiguity, so lower-casing
// an admitted host cannot produce a name other than the one the client
// resolves and sends, up to ASCII case. It does not make every wire transform
// an identity. A bracketed IPv6 literal carrying a zone is ASCII and is
// admitted, and Go's HTTP/1 writer still drops the zone from the Host header.
// Ranging over the string decodes invalid UTF-8 to U+FFFD, which is above
// U+007F, so malformed bytes are rejected too. Pure: no I/O.
func ASCIIHost(host string) error {
	for _, r := range host {
		if r > unicode.MaxASCII {
			return fmt.Errorf("%w: %q; write an internationalized name in punycode", ErrNonASCIIHost, host)
		}
	}

	return nil
}
