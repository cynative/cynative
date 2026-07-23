package redact_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// FuzzRedact pins panic-freedom and the fail-closed redaction contract over
// arbitrary response bytes (#181). Seed corpus covers known secret shapes and
// benign prose so go test exercises the interesting branches without -fuzz.
func FuzzRedact(f *testing.F) {
	f.Add("token=ghp_" + strings.Repeat("a", 36) + " end")
	f.Add("a perfectly ordinary sentence with no secrets")
	f.Add(`{"access_token":"abc123secretvalue","expires_in":3600}`)
	f.Add("Bearer eyJhbGci.eyJzdWIi.sig123_-")
	f.Add("")
	f.Add(string([]byte{0xff, 0xfe, 'h', 'i'}))

	r := redact.New()
	f.Fuzz(func(t *testing.T, s string) {
		got := r.Redact(s)
		if again := r.Redact(got); again != got {
			t.Fatalf("Redact is not idempotent: first=%q second=%q", got, again)
		}
		// A fired rule must leave a labeled placeholder, never the raw secret
		// shape we seeded. Only assert on inputs we know contain a classic PAT.
		const pat = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if strings.Contains(s, pat) && strings.Contains(got, pat) {
			t.Fatalf("classic GitHub PAT survived redaction: %q", got)
		}
		if strings.Contains(s, pat) && !strings.Contains(got, "[REDACTED:") {
			t.Fatalf("classic GitHub PAT matched but left no placeholder: %q", got)
		}
	})
}

// FuzzRedactHeader pins panic-freedom and denylist / Location-exemption
// behavior over arbitrary header values (#181).
func FuzzRedactHeader(f *testing.F) {
	f.Add("Authorization", "Bearer abc")
	f.Add("Location", "https://x/o?X-Amz-Signature=keepme&t=1")
	f.Add("X-Custom", "token=ghp_"+strings.Repeat("a", 36))
	f.Add("Content-Type", "application/json")
	f.Add("Set-Cookie", "session=topsecret; Path=/")

	r := redact.New()
	f.Fuzz(func(t *testing.T, name, value string) {
		if name == "" {
			return
		}
		h := http.Header{}
		h.Set(name, value)
		locBefore := h.Get("Location")
		r.RedactHeader(h)

		canon := http.CanonicalHeaderKey(strings.ReplaceAll(
			http.CanonicalHeaderKey(name), "_", "-",
		))
		switch canon {
		case "Authorization", "Set-Cookie", "Proxy-Authorization",
			"Private-Token", "Job-Token", "Deploy-Token",
			"X-Gitlab-Static-Object-Token", "X-Amz-Security-Token",
			"X-Ms-Authorization-Auxiliary":
			if value == "" {
				return
			}
			if got := h.Get(name); got != "[REDACTED:header]" {
				t.Fatalf("%s denylist miss: %q", canon, got)
			}
		case "Location":
			if got := h.Get("Location"); got != locBefore {
				t.Fatalf("Location must stay exempt: before=%q after=%q", locBefore, got)
			}
		}
	})
}
