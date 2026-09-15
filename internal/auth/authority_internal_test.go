package auth

import (
	"errors"
	"testing"
)

func TestASCIIHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"plain ascii", "api.github.com", false},
		{"punycode passes", "xn--i-9bb.example", false},
		{"uppercase ascii passes", "API.GitHub.com", false},
		{"ipv4 literal passes", "203.0.113.7", false},
		{"ipv6 zone is ascii and passes", "fe80::1%eth0", false},
		{"empty passes", "", false},
		{"U+0130 folds to ascii and is rejected", "api.gİthub.com", true},
		{"U+212A folds to ascii and is rejected", "gKthub.com", true},
		{"non-folding unicode is rejected", "straße.example", true},
		{"unicode whitespace is rejected", "api.github.com ", true},
		{"invalid utf-8 decodes to U+FFFD and is rejected", "api.\xff.com", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ASCIIHost(tc.host)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("ASCIIHost(%q) error = %v, want error %v", tc.host, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrNonASCIIHost) {
				t.Fatalf("ASCIIHost(%q) = %v, want ErrNonASCIIHost", tc.host, err)
			}
		})
	}
}
