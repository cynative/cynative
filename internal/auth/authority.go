package auth

import (
	"fmt"

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
// connector is pinned to. The host gates receive a port-stripped hostname
// (auth.AuthorizeHost passes req.URL.Hostname()) and the dial guard sees only an
// IP, so this is the only place the port is bound: without it a model can reach
// a different TLS listener on the pinned host or IP and have the injected
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
