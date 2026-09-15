package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/authtest"
)

var (
	_ auth.Provider         = (*authoritySpyProvider)(nil)
	_ auth.ActionAuthorizer = (*authoritySpyProvider)(nil)
	_ auth.CACertProvider   = (*authoritySpyProvider)(nil)
	_ auth.AddrAuthorizer   = (*authoritySpyProvider)(nil)
)

// authoritySpyProvider records the authority the gates were handed and whether
// the credential was ever attached. It records the port as well as the host,
// because an authority that survives the pipeline intact still says nothing
// about which authority a policy authorized.
//
// It embeds an [authtest.LoopbackProvider] for everything it does not record,
// so it authorizes every host and every resolved address and supplies the test
// server's CA. The address half is load-bearing: without it the floor in
// [auth.AuthorizeAddr] rejects the httptest server's loopback address and every
// row that should reach the server would die at the dial instead. This test's
// business is the spelling of the authority; the address floor is pinned by the
// dial-guard tests in transport_internal_test.go.
//
// The fields are read after Execute returns, and every gate runs synchronously
// on the calling goroutine, so no synchronization is needed. Recording rather
// than failing inside the double keeps the assertions in the rows, where each
// one can say what it expected.
type authoritySpyProvider struct {
	*authtest.LoopbackProvider

	host     string // the host AuthorizesHost was given; "" when it never ran.
	port     string // the port AuthorizeAction was given; "" for an absent port.
	injected bool   // whether InjectAuth ran.
}

func (p *authoritySpyProvider) AuthorizesHost(
	_ context.Context, host string, _ authreq.ProviderArgs,
) (bool, error) {
	p.host = host

	return true, nil
}

func (p *authoritySpyProvider) AuthorizeAction(_ context.Context, v authreq.View, _ authreq.ProviderArgs) error {
	p.port = v.Port

	return nil
}

// InjectAuth records the call and then attaches the loopback provider's bearer
// token, so p.injected means the credential really went on the request rather
// than that a no-op ran.
func (p *authoritySpyProvider) InjectAuth(req *http.Request, args authreq.ProviderArgs) error {
	p.injected = true

	return p.LoopbackProvider.InjectAuth(req, args)
}

// TestAuthorityInvariant asserts, for each adversarial spelling of an authority,
// that the request is either refused before any gate classified it and before
// the credential was attached, or reaches the server under exactly the
// authority the gate authorized.
//
// ASCII case is the only difference the oracle forgives, because DNS is
// case-insensitive over ASCII and over nothing else. equalAuthority is where
// that is enforced, and TestEqualAuthority pins it.
//
// The hosts are written as \u escapes so a row stays readable in a diff and no
// editor can silently rewrite one. Every one of them is under .example
// (RFC 6761), so no row can resolve to a domain someone else controls: under a
// mutation that admits these hosts, the suite dials them with a credential
// attached.
func TestAuthorityInvariant(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string // substituted for the test server's host; "" keeps the server's own.
		want string // "refused", "admitted" or "sent".
	}{
		{"plain ascii reaches the server", "", "sent"},
		{"U+0130 folds to ascii", "\u0130.example", "refused"},
		{"U+212A folds to ascii", "g\u212athub.example", "refused"},
		{"non-folding unicode", "stra\u00dfe.example", "refused"},
		{"non-breaking space", "space.example\u00a0", "refused"},
		{"ideographic space", "space.example\u3000", "refused"},
		// Raw invalid UTF-8 cannot reach here: the arguments are JSON, and both
		// the marshal in makeArgs and the unmarshal in do replace a bad byte
		// with U+FFFD. TestASCIIHost pins the raw-byte input directly.
		{"replacement rune in the host", "exa\ufffdmple.example", "refused"},
		{"punycode is admitted", "xn--i-9bb.example", "admitted"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			received := make(chan string, 1)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				//nolint:forbidigo // Server-side inbound request: the wire authority is what this test reads.
				received <- r.Host
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)

			p := &authoritySpyProvider{
				LoopbackProvider: &authtest.LoopbackProvider{
					ProviderName: "invariant",
					CACert:       tlsCertBase64(t, srv),
					Token:        "sentinel-token",
				},
			}

			target := srv.URL + "/p"
			if tc.host != "" {
				target = "https://" + tc.host + "/p"
			}

			args := makeArgs(t, map[string]any{"url": target, "auth_provider": "invariant"})
			_, _, err := NewClient().Execute(context.Background(), args, []auth.Provider{p})

			// "sent" is the default arm, so a mistyped want cannot leave a row
			// asserting nothing: it runs the strictest of the three instead.
			switch tc.want {
			case "refused":
				assertRefused(t, tc.host, err, p)
			case "admitted":
				assertAdmitted(t, tc.host, err, p)
			default:
				assertSent(t, err, p, received)
			}
		})
	}
}

// assertRefused checks that the host was turned away by the admission rule,
// that the credential never went out, and that no gate ever classified the
// host. The last two are what make the position of the rule observable rather
// than only its presence: move the rule down and the gate has already been
// handed a folded spelling of a name the wire would never carry.
//
// The order of the three is deliberate, so that each one is the first to fire
// for some way of getting this wrong: deleting the rule leaves the sentinel
// check, moving it below Inject leaks the credential, and moving it anywhere
// between the gates leaks the classification.
func assertRefused(t *testing.T, host string, err error, p *authoritySpyProvider) {
	t.Helper()

	if !errors.Is(err, auth.ErrNonASCIIHost) {
		t.Fatalf("host %q: Execute = %v, want auth.ErrNonASCIIHost", host, err)
	}
	if p.injected {
		t.Fatalf("host %q was refused, but the credential was attached first", host)
	}
	if p.host != "" {
		t.Fatalf("host %q was refused, but a gate had already classified it as %q", host, p.host)
	}
}

// assertAdmitted checks that the host cleared the admission rule. Punycode is
// ASCII, so it is admitted and then fails at DNS or the dial, which is expected.
// The credential check keeps the row honest: without it a rule that rejected
// punycode under some other error would pass silently.
func assertAdmitted(t *testing.T, host string, err error, p *authoritySpyProvider) {
	t.Helper()

	if errors.Is(err, auth.ErrNonASCIIHost) {
		t.Fatalf("host %q was refused as non-ASCII", host)
	}
	if !p.injected {
		t.Fatalf("host %q never reached the credential: Execute = %v", host, err)
	}
}

// assertSent checks that the authority the gates authorized is the authority
// the server received.
func assertSent(t *testing.T, err error, p *authoritySpyProvider, received <-chan string) {
	t.Helper()

	if err != nil {
		t.Fatalf("Execute = %v, want the request to reach the server", err)
	}

	authorized := net.JoinHostPort(p.host, p.port)
	if wire := <-received; !equalAuthority(authorized, wire) {
		t.Fatalf("the gate authorized %q but the server received %q", authorized, wire)
	}
}

// equalAuthority reports whether the authority the gate authorized and the one
// the server received name the same endpoint. The two hosts must be the same
// ASCII string up to case, and the two ports must be identical. Every row that
// reaches the server carries an explicit port, so there is no default to apply
// and an absent port on either side is a mismatch.
//
// Neither [strings.EqualFold] nor [strings.ToLower] alone can decide this.
// Both apply Unicode case mapping, which turns U+212A into "k" and U+017F into
// "s", so either one would call two different DNS names equal and would accept
// exactly the confusion this test exists to catch. A host carrying any rune
// above U+007F is therefore rejected before the comparison, not folded into it.
func equalAuthority(authorized, wire string) bool {
	ah, ap, aerr := net.SplitHostPort(authorized)
	wh, wp, werr := net.SplitHostPort(wire)
	if aerr != nil || werr != nil {
		return false
	}

	if !asciiOnly(ah) || !asciiOnly(wh) {
		return false
	}

	// SA6005 reads this as a slower strings.EqualFold. It is not one: the guard
	// above is what makes ToLower an ASCII fold here, and EqualFold would undo it.
	//nolint:staticcheck // SA6005 suggests the Unicode-folding call this function exists to avoid.
	return strings.ToLower(ah) == strings.ToLower(wh) && ap == wp
}

// asciiOnly reports whether s is all ASCII. Ranging over the string decodes
// invalid UTF-8 to U+FFFD, which is above U+007F, so malformed bytes are
// rejected too. It mirrors [auth.ASCIIHost], the rule under test.
func asciiOnly(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}

	return true
}

// TestEqualAuthority pins the oracle itself. The two folding rows are the
// regression guard: U+212A and U+017F are the runes that make Unicode case
// folding unsafe for a DNS name, and a switch back to [strings.EqualFold] or a
// bare [strings.ToLower] turns both of them green.
func TestEqualAuthority(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		authorized, wire string
		want             bool
	}{
		{"identical", "example.com:443", "example.com:443", true},
		{"ascii case only", "ExAmple.com:443", "example.COM:443", true},
		{"U+212A is not k", "gkthub.example:443", "g\u212athub.example:443", false},
		{"U+017F is not s", "s.example:443", "\u017f.example:443", false},
		{"identical non-ascii is still rejected", "stra\u00dfe.example:443", "stra\u00dfe.example:443", false},
		{"a different port is a different endpoint", "example.com:443", "example.com:8443", false},
		{"an absent port is not an authority", "example.com:443", "example.com", false},
		{"an unparseable authority is not an authority", "example.com", "example.com:443", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := equalAuthority(tc.authorized, tc.wire); got != tc.want {
				t.Fatalf("equalAuthority(%q, %q) = %v, want %v", tc.authorized, tc.wire, got, tc.want)
			}
		})
	}
}
