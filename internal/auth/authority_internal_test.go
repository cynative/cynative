package auth

import (
	"errors"
	"testing"
)

// TestAdmitHost pins both admission sentinels and, with them, the byte the
// ASCII scan compares against.
//
// The 0x7f and 0x80 rows are the pair that separates that comparison from an
// off-by-one. Every other row the ASCII scan rejects starts its non-ASCII run
// with a UTF-8 lead byte, which is 0xc2 or above, so a scan that let 0x80
// through would still reject all of them. A raw 0x80 is reachable from the tool
// arguments without any invalid UTF-8 in them: [url.Parse] decodes the host of
// "https://api.%80.com/x" to exactly the 0x80 row's string.
//
// The zone rows are the case the ASCII rule alone does not cover. The gates
// classify a lower-cased hostname and the dial keeps the case, which is
// harmless for a DNS name and is not harmless for a zone: "%ETH0" would be
// authorized as "%eth0".
func TestAdmitHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
		want error // nil when the host is admitted.
	}{
		{"plain ascii", "api.github.com", nil},
		{"punycode passes", "xn--i-9bb.example", nil},
		{"uppercase ascii passes", "API.GitHub.com", nil},
		{"ipv4 literal passes", "203.0.113.7", nil},
		{"unzoned ipv6 literal passes", "2001:db8::1", nil},
		{"ipv6 loopback passes", "::1", nil},
		{"0x7f is ascii and passes", "api.\x7f.com", nil},
		{"empty passes", "", nil},
		// A percent reaches a hostname outside a zone too: this is the host of
		// "https://api.%25.com/x" once [url.Parse] has decoded it. It names no
		// interface and nothing in it is case-sensitive, so searching for "%"
		// instead of parsing the address would refuse it for no reason.
		{"a percent outside an ip literal is not a zone", "api.%.com", nil},
		{"U+0130 folds to ascii and is rejected", "api.g\u0130thub.com", ErrNonASCIIHost},
		{"U+212A folds to ascii and is rejected", "g\u212Athub.com", ErrNonASCIIHost},
		{"non-folding unicode is rejected", "stra\u00dfe.example", ErrNonASCIIHost},
		{"unicode whitespace is rejected", "api.github.com\u00a0", ErrNonASCIIHost},
		{"0x80 alone is rejected", "api.\x80.com", ErrNonASCIIHost},
		{"a byte no utf-8 sequence can hold is rejected", "api.\xff.com", ErrNonASCIIHost},
		{"a zoned link-local literal is rejected", "fe80::1%eth0", ErrZonedHost},
		{"a mixed-case zone is rejected", "2001:db8::1%ETH0", ErrZonedHost},
		{"a zoned ipv4-mapped literal is rejected", "::ffff:203.0.113.7%eth0", ErrZonedHost},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := AdmitHost(tc.host)
			if !errors.Is(err, tc.want) {
				t.Fatalf("AdmitHost(%q) = %v, want %v", tc.host, err, tc.want)
			}
		})
	}
}
