package transport

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/auth/authreq"
	"github.com/cynative/cynative/internal/auth/authtest"
)

var (
	_ auth.Provider           = (*authoritySpyProvider)(nil)
	_ auth.ActionAuthorizer   = (*authoritySpyProvider)(nil)
	_ auth.CACertProvider     = (*authoritySpyProvider)(nil)
	_ auth.AddrAuthorizer     = (*authoritySpyProvider)(nil)
	_ auth.ServerNameProvider = (*authoritySpyProvider)(nil)
)

// undecodableCA is a CA value that is not base64, so [auth.BuildTLSConfig]
// fails to decode it and configureTransport returns the failure. [Client.do]
// reaches configureTransport after Inject and before it hands the request to
// the client, so a row carrying this one ends there: every gate and the
// credential have run, and no name was ever resolved.
const undecodableCA = "!"

// authoritySpyProvider records the authority each gate was handed and whether
// the credential was ever attached. It keeps the two gates' hostnames apart and
// records the port, because an authority that survives the pipeline intact
// still says nothing about which authority a policy authorized, and one
// assembled from two gates' observations says nothing about whether the two
// gates agreed on it.
//
// It embeds an [authtest.LoopbackProvider] for everything it does not record,
// so it authorizes every host and every resolved address and supplies whatever
// CA its row configured. The address half is load-bearing: without it the
// floor in [auth.AuthorizeAddr] rejects the httptest server's loopback address
// and every row that should reach the server would die at the dial instead.
// This test's business is the spelling of the authority; the address floor is
// pinned by the dial-guard tests in transport_internal_test.go.
//
// Every recorded field here is written from AuthorizesHost, AuthorizeAction or
// InjectAuth, which [Client.do] calls in that order on the calling goroutine
// before the request is dialed, and read after Execute returns, so no
// synchronization is needed. Address authorization is the gate that does not
// run there: it runs from the dialer's ControlContext hook, on the dialing
// goroutine, and this double records nothing from it. Recording rather than
// failing inside the double keeps the assertions in the rows, where each one
// can say what it expected.
//
// serverName is the one field that goes the other way: the row writes it
// before Execute and the double only reads it, from that same goroutine.
type authoritySpyProvider struct {
	*authtest.LoopbackProvider

	serverName string // the TLS ServerName to override with; "" leaves verification on the host.

	hostGateHost   string // the host AuthorizesHost was given; "" when it never ran.
	actionGateHost string // the hostname AuthorizeAction was given; "" when it never ran.
	port           string // the port AuthorizeAction was given; "" for an absent port.
	injected       bool   // whether InjectAuth ran.
}

func (p *authoritySpyProvider) AuthorizesHost(
	_ context.Context, host string, _ authreq.ProviderArgs,
) (bool, error) {
	p.hostGateHost = host

	return true, nil
}

func (p *authoritySpyProvider) AuthorizeAction(_ context.Context, v authreq.View, _ authreq.ProviderArgs) error {
	p.actionGateHost = v.Hostname
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

// ServerNameData supplies the TLS ServerName override the transport already
// offers connectors through [auth.ServerNameProvider], which the kubernetes
// connector uses for its tls-server-name setting. A row that reaches the test
// server under a substituted host needs it, because the httptest certificate
// names the server and not the row's host. It returns "" for every other row,
// and [auth.BuildTLSConfig] then leaves ServerName unset, so no row's TLS
// verification changes unless that row asked for it.
func (p *authoritySpyProvider) ServerNameData(_ context.Context, _ authreq.ProviderArgs) (string, error) {
	return p.serverName, nil
}

// TestAuthorityInvariant asserts, for each adversarial spelling of an authority,
// that the request is either refused before any gate classified it and before
// the credential was attached, or reaches the server under exactly the
// authority the gate authorized.
//
// ASCII case is the only difference the oracle forgives, because DNS is
// case-insensitive over ASCII and over nothing else. equalAuthority is where
// that is enforced, and TestEqualAuthority pins it. Two rows reach the server,
// and the second is where that forgiveness is exercised against a real request
// rather than against the oracle alone: one addresses the loopback literal the
// server binds, which has no case, and one addresses it as LOCALHOST, which
// the gates classify lower-cased while the wire keeps the spelling as written.
//
// The Unicode hosts are written as \u escapes so a row stays readable in a
// diff and no editor can silently rewrite one; the percent-encoded row is ASCII
// as written and only becomes a non-ASCII host once [url.Parse] decodes it. Every
// name here is under .example, which RFC 6761 reserves from registration, so no row
// can resolve to a domain someone else has registered; that reservation binds
// registries, not resolvers, so a hijacking or wildcard resolver could still
// answer for one of these hosts. The one address literal is under 2001:db8::/32,
// which RFC 3849 reserves for documentation. None of them can reach a resolver
// even so: only a row that means to reach the test server is handed a CA that
// decodes, so a mutation that admitted one of these hosts ends the run in
// configureTransport rather than dialing whatever answers with a credential
// attached.
func TestAuthorityInvariant(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		host     string // substituted for the test server's host; "" keeps the server's own.
		atServer bool   // host names the test server: give it the server's port and its certificate's name.
		want     string // "refused", "admitted" or "sent".
		sentinel error  // the admission sentinel a "refused" row must report.
	}{
		{"plain ascii reaches the server", "", false, "sent", nil},
		// The resolver answers LOCALHOST from the hosts file, case-insensitively
		// and without a query, so this row reaches the same server the row above
		// does. [authreq.NewView] lower-cases the hostname it hands both gates
		// while the wire carries the spelling as written, which is the one
		// difference equalAuthority forgives and the only difference an accepted
		// name is allowed to have.
		{"mixed-case ascii reaches the server", "LOCALHOST", true, "sent", nil},
		{"U+0130 folds to ascii", "\u0130.example", false, "refused", auth.ErrNonASCIIHost},
		{"U+212A folds to ascii", "g\u212athub.example", false, "refused", auth.ErrNonASCIIHost},
		{"non-folding unicode", "stra\u00dfe.example", false, "refused", auth.ErrNonASCIIHost},
		{"non-breaking space", "space.example\u00a0", false, "refused", auth.ErrNonASCIIHost},
		{"ideographic space", "space.example\u3000", false, "refused", auth.ErrNonASCIIHost},
		// A raw invalid byte cannot survive the arguments: they are JSON, and
		// both the marshal in makeArgs and the unmarshal in do replace a bad
		// byte with U+FFFD. Percent-encoding is how one actually arrives, and
		// it is pure ASCII until [url.Parse] decodes the host.
		{"replacement rune in the host", "exa\ufffdmple.example", false, "refused", auth.ErrNonASCIIHost},
		{"percent-encoded invalid byte", "exa%FFmple.example", false, "refused", auth.ErrNonASCIIHost},
		// The zone survives every ASCII rule intact and is still not one
		// spelling: the gates are handed "%eth0" and the dial keeps "%ETH0".
		// "%25" is how a zone is written in a URL, so this row is ASCII as
		// typed and carries the zone only once [url.Parse] has decoded it.
		{"mixed-case ipv6 zone", "[2001:db8::1%25ETH0]", false, "refused", auth.ErrZonedHost},
		// Punycode is ASCII, so the rule admits it, and the name it spells is
		// registered to nobody, so this row must never go looking for it. It
		// stops at its own CA instead and reaches no server.
		{"punycode is admitted, never dialed", "xn--i-9bb.example", false, "admitted", nil},
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

			// Only a row that means to reach the server is handed a CA that
			// decodes. The two names tested here are the two non-default arms
			// of the switch below, so a mistyped want still gets a working CA
			// and runs the strictest of the three checks.
			ca := tlsCertBase64(t, srv)
			if tc.want == "refused" || tc.want == "admitted" {
				ca = undecodableCA
			}

			p := &authoritySpyProvider{
				LoopbackProvider: &authtest.LoopbackProvider{
					ProviderName: "invariant",
					CACert:       ca,
					Token:        "sentinel-token",
				},
			}

			target := srv.URL + "/p"
			if tc.host != "" {
				host := tc.host
				if tc.atServer {
					// A substituted host has to carry the server's port to
					// reach it, and the httptest certificate names the server
					// rather than this host, so the provider overrides the
					// name the handshake verifies.
					host = net.JoinHostPort(host, serverPort(t, srv))
					p.serverName = certDNSName(t, srv)
				}
				target = "https://" + host + "/p"
			}

			args := makeArgs(t, map[string]any{"url": target, "auth_provider": "invariant"})
			_, _, err := NewClient().Execute(context.Background(), args, []auth.Provider{p})

			// "sent" is the default arm, so a mistyped want cannot leave a row
			// asserting nothing: it runs the strictest of the three instead.
			switch tc.want {
			case "refused":
				assertRefused(t, tc.host, tc.sentinel, err, p)
			case "admitted":
				assertAdmitted(t, tc.host, err, p)
			default:
				assertSent(t, err, p, received)
			}
		})
	}
}

// serverPort returns the port the test server listens on. A row that
// substitutes the host has to carry that port to reach it, and every row that
// reaches it is compared on the whole authority, port included.
func serverPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split the test server's address %q: %v", srv.Listener.Addr(), err)
	}

	return port
}

// certDNSName returns the first name the test server's certificate carries.
// A row that addresses the server under a substituted host is verified against
// that name, read off the certificate rather than copied from httptest, so the
// row survives a change to the names httptest issues.
func certDNSName(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	names := srv.Certificate().DNSNames
	if len(names) == 0 {
		t.Fatal("the test server's certificate carries no DNS name to verify against")
	}

	return names[0]
}

// assertRefused checks that the host was turned away by the admission rule
// under the sentinel its row named, that the credential never went out, and
// that no gate ever classified the host. The last two are what make the
// position of the rule observable rather than only its presence: move the rule
// down and the gate has already been handed a folded spelling of a name the
// wire would never carry.
//
// The order of the three is deliberate, so that each one is the first to fire
// for some way of getting this wrong: deleting the rule leaves the sentinel
// check, moving it below Inject leaks the credential, and moving it anywhere
// between the gates leaks the classification. A row that names no sentinel
// fails the first check, since no error is [errors.Is] a nil target.
func assertRefused(t *testing.T, host string, sentinel, err error, p *authoritySpyProvider) {
	t.Helper()

	if !errors.Is(err, sentinel) {
		t.Fatalf("host %q: Execute = %v, want %v", host, err, sentinel)
	}
	if p.injected {
		t.Fatalf("host %q was refused, but the credential was attached first", host)
	}
	if p.hostGateHost != "" || p.actionGateHost != "" {
		t.Fatalf("host %q was refused, but a gate had already classified it (host gate %q, action gate %q)",
			host, p.hostGateHost, p.actionGateHost)
	}
}

// assertAdmitted checks that the host cleared the admission rule and that the
// run then ended where the row arranged, with nothing resolved and nothing
// dialed. Punycode is ASCII and names no interface, so the rule admits it, and
// the credential check keeps the row honest: without it a rule that rejected
// punycode under some other error would pass silently.
//
// The decode failure is the third check and it is what keeps the row offline.
// The row supplies a CA that is not base64, [Client.do] reaches
// configureTransport after Inject and before it sends, and that decode is the
// error this expects. A row that went to the network would report a lookup or
// a dial error instead, and this is what would catch it.
func assertAdmitted(t *testing.T, host string, err error, p *authoritySpyProvider) {
	t.Helper()

	if errors.Is(err, auth.ErrNonASCIIHost) || errors.Is(err, auth.ErrZonedHost) {
		t.Fatalf("host %q was refused by the admission rule: %v", host, err)
	}
	if !p.injected {
		t.Fatalf("host %q never reached the credential: Execute = %v", host, err)
	}

	if _, ok := errors.AsType[base64.CorruptInputError](err); !ok {
		t.Fatalf("host %q: Execute = %v, want the run to end at the undecodable CA", host, err)
	}
}

// assertSent checks that both gates classified the same hostname and that the
// authority they authorized is the authority the server received. Without the
// first half the authority under test is assembled from two separate
// observations, and a hostname substituted between the gates is invisible.
//
// The two hostnames are compared byte for byte rather than through
// equalAuthority: [Client.do] hands both gates the same v.Hostname, so any
// difference at all means the host was derived twice, which is the defect class
// this file exists to catch.
func assertSent(t *testing.T, err error, p *authoritySpyProvider, received <-chan string) {
	t.Helper()

	if err != nil {
		t.Fatalf("Execute = %v, want the request to reach the server", err)
	}

	if p.hostGateHost != p.actionGateHost {
		t.Fatalf("the host gate classified %q but the action gate classified %q",
			p.hostGateHost, p.actionGateHost)
	}

	authorized := net.JoinHostPort(p.hostGateHost, p.port)
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
// Neither [strings.EqualFold] nor a bare [strings.ToLower] can safely decide
// this alone. [strings.EqualFold] case-folds both U+212A and U+017F to their
// ASCII look-alikes ("k" and "s"), so it would call two different DNS names
// equal. [strings.ToLower] folds U+212A to "k" the same way, so it is not a
// safe substitute either, even though it happens to leave U+017F unchanged. A
// host carrying any rune above U+007F is therefore rejected before either
// comparison runs, not folded into it.
func equalAuthority(authorized, wire string) bool {
	ah, ap, aerr := net.SplitHostPort(authorized)
	wh, wp, werr := net.SplitHostPort(wire)
	if aerr != nil || werr != nil {
		return false
	}

	if !asciiOnly(ah) || !asciiOnly(wh) {
		return false
	}

	// SA6005 reads this as a slower strings.EqualFold. Behind the guard above
	// the two are equivalent, because over ASCII, folding and lower-casing agree
	// and neither changes the length. What is unsafe is dropping the guard:
	// EqualFold then folds U+212A and U+017F onto "k" and "s" and calls two
	// different DNS names equal. Keep the two together: the fold is only an
	// ASCII fold because the guard already ran.
	//nolint:staticcheck // SA6005 suggests a fold that is only ASCII-safe because of the guard above.
	return strings.ToLower(ah) == strings.ToLower(wh) && ap == wp
}

// asciiOnly reports whether s is all ASCII. It mirrors the ASCII half of
// [auth.AdmitHost], the rule under test, and scans bytes the same way: a byte
// of 0x80 or above belongs either to a rune above U+007F or to a malformed
// sequence, and neither is admitted, so no decoding step is involved on either
// side. The zone half of the rule is not mirrored here, because a zoned host
// never reaches this oracle: the rule refuses it and the row asserts the
// refusal instead.
func asciiOnly(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}

// TestEqualAuthority pins the oracle itself. Both folding rows fire only once
// the asciiOnly guards are gone: with the guards kept, [strings.EqualFold] and
// the current ToLower comparison agree on every ASCII pair, so swapping one for
// the other changes no row here. Removing the guards is the unsafe part, and
// the two rows then separate the substitutes: the U+212A row fails under
// either, since ToLower and EqualFold both fold it to "k"; the U+017F row fails
// only under EqualFold, since ToLower leaves U+017F unchanged and would still
// reject that row correctly.
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
