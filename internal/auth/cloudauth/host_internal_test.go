package cloudauth

import (
	"errors"
	"testing"
)

func TestNormalizeHost_accepts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
		want string
	}{
		{name: "plain", host: "compute.googleapis.com", want: "compute.googleapis.com"},
		{name: "uppercase lowered", host: "Compute.GoogleAPIs.Com", want: "compute.googleapis.com"},
		{name: "surrounding spaces trimmed", host: "  iam.googleapis.com  ", want: "iam.googleapis.com"},
		{name: "trailing dot trimmed", host: "iam.googleapis.com.", want: "iam.googleapis.com"},
		{name: "port stripped", host: "management.azure.com:443", want: "management.azure.com"},
		// netip.ParseAddr cannot parse these non-canonical numeric forms, so they
		// pass NormalizeHost and are blocked by each cloud's suffix allowlist.
		{name: "dword passes (blocked downstream)", host: "2130706433", want: "2130706433"},
		{name: "octal passes (blocked downstream)", host: "0177.0.0.1", want: "0177.0.0.1"},
		{name: "hex passes (blocked downstream)", host: "0x7f.0.0.1", want: "0x7f.0.0.1"},
		{name: "localhost passes (blocked by per-cloud rejectHost)", host: "localhost", want: "localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeHost(tc.host)
			if err != nil {
				t.Fatalf("NormalizeHost(%q): unexpected err %v", tc.host, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestNormalizeHost_rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
	}{
		{name: "empty", host: ""},
		{name: "userinfo at-sign", host: "foo@iam.googleapis.com"},
		// Non-ASCII / IDNA fullwidth-digit smuggle — rejected at step 5.
		{name: "fullwidth digit smuggle", host: "１９２．１６８．１．１"},
		{name: "cyrillic homoglyph", host: "іam.googleapis.com"},
		// idna idempotency failure (bracketed forms carry a disallowed rune).
		{name: "bracketed ipv6 loopback", host: "[::1]"},
		{name: "bracketed ipv4-mapped imds", host: "[::ffff:169.254.169.254]"},
		{name: "bracketed zoned ipv6", host: "[fe80::1%eth0]"},
		// netip.ParseAddr succeeds → step 7 rejects the literal.
		{name: "ipv4 imds literal", host: "169.254.169.254"},
		{name: "ipv4 loopback literal", host: "127.0.0.1"},
		{name: "ipv4 rfc1918 literal", host: "10.0.0.5"},
		{name: "ipv4 public literal", host: "8.8.8.8"},
		// Bare (unbracketed) IPv6 literals have 2+ colons → rejected at the
		// port-strip step (a host:port has exactly one colon).
		{name: "bare ipv6 loopback", host: "::1"},
		{name: "bare ipv6 unspecified", host: "::"},
		{name: "bare ipv6 link-local", host: "fe80::1"},
		{name: "bare ipv6 global", host: "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NormalizeHost(tc.host)
			if !errors.Is(err, ErrInvalidHost) {
				t.Errorf("NormalizeHost(%q) err = %v, want ErrInvalidHost", tc.host, err)
			}
		})
	}
}

func TestIsIPLiteral(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
		want bool
	}{
		{name: "bracketed ipv6", host: "[::1]", want: true},
		{name: "bare colon ipv6", host: "::1", want: true},
		{name: "bare ipv4-mapped imds", host: "::ffff:169.254.169.254", want: true},
		{name: "bare ipv4 imds", host: "169.254.169.254", want: true},
		{name: "bare ipv4 loopback", host: "127.0.0.1", want: true},
		// Non-canonical numeric forms are NOT IP literals to netip; IsIPLiteral
		// returns false for them (they are rejected by the suffix allowlist).
		{name: "dword not a literal", host: "2130706433", want: false},
		{name: "octal not a literal", host: "0177.0.0.1", want: false},
		{name: "hex not a literal", host: "0x7f.0.0.1", want: false},
		{name: "hostname", host: "compute.googleapis.com", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := IsIPLiteral(tc.host); got != tc.want {
				t.Errorf("IsIPLiteral(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestHostOf(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "https prefix stripped", raw: "https://compute.googleapis.com/", want: "compute.googleapis.com"},
		{name: "http prefix stripped", raw: "http://compute.googleapis.com/", want: "compute.googleapis.com"},
		{name: "no scheme", raw: "management.azure.com", want: "management.azure.com"},
		{name: "path stripped", raw: "https://compute.googleapis.com/compute/v1/", want: "compute.googleapis.com"},
		// Lowercase scheme + uppercase host exercises strings.ToLower. NOTE: an
		// uppercase scheme ("HTTPS://") is NOT stripped (TrimPrefix is
		// case-sensitive), so do not use one here — it would resolve to "https:".
		{name: "uppercase host lowered", raw: "https://Compute.GoogleAPIs.Com/", want: "compute.googleapis.com"},
		{name: "trailing dot trimmed", raw: "https://iam.googleapis.com./", want: "iam.googleapis.com"},
		{name: "host port retained", raw: "https://management.azure.com:443/foo", want: "management.azure.com:443"},
		{name: "empty", raw: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := HostOf(tc.raw); got != tc.want {
				t.Errorf("HostOf(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
