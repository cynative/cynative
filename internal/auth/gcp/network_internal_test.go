package gcp

import (
	"errors"
	"testing"
)

func TestParseHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		host        string
		wantService string
		wantLoc     string
		wantErr     bool
	}{
		// accepts
		{name: "plain global", host: "iam.googleapis.com", wantService: "iam"},
		{name: "compute global", host: "compute.googleapis.com", wantService: "compute"},
		{name: "mtls", host: "compute.mtls.googleapis.com", wantService: "compute"},
		{
			name:        "legacy locational",
			host:        "us-central1-aiplatform.googleapis.com",
			wantService: "aiplatform",
			wantLoc:     "us-central1",
		},
		{
			name:        "newer regional rep",
			host:        "aiplatform.us-central1.rep.googleapis.com",
			wantService: "aiplatform",
			wantLoc:     "us-central1",
		},
		{name: "bucket vhost storage", host: "my-bucket.storage.googleapis.com", wantService: "storage"}, // A6
		{name: "trailing dot stripped", host: "iam.googleapis.com.", wantService: "iam"},
		{name: "uppercase normalized", host: "Compute.GoogleAPIs.Com", wantService: "compute"},
		// www.googleapis.com resolves from PATH, not host — ParseHost returns
		// a sentinel empty-service candidate flagged for path resolution.
		{name: "www compound needs path", host: "www.googleapis.com", wantService: wwwCompoundSentinel},
		// rejects (SSRF / spoof / PSC / private)
		{name: "ipv4 literal", host: "169.254.169.254", wantErr: true},             // A3
		{name: "metadata server", host: "metadata.google.internal", wantErr: true}, // A3
		{name: "localhost", host: "localhost", wantErr: true},                      // A3
		{name: "rfc1918", host: "10.0.0.5", wantErr: true},
		{name: "ipv6", host: "[::1]", wantErr: true},
		{name: "psc rep", host: "x.p.rep.googleapis.com", wantErr: true}, // A4
		{name: "private vip", host: "private.googleapis.com", wantErr: true},
		{name: "restricted vip", host: "restricted.googleapis.com", wantErr: true},
		{name: "non-googleapis run.app", host: "svc.run.app", wantErr: true},
		{name: "non-googleapis pkg.dev", host: "x.pkg.dev", wantErr: true},
		{name: "suffix spoof", host: "iam.googleapis.com.evil.com", wantErr: true}, // A2
		{name: "userinfo", host: "foo@iam.googleapis.com", wantErr: true},          // A10
		{name: "idn homoglyph", host: "іam.googleapis.com", wantErr: true},         // A10 (Cyrillic 'і')
		{name: "empty", host: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseHost(tc.host)
			if tc.wantErr {
				if !errors.Is(err, ErrHostPattern) {
					t.Fatalf("ParseHost(%q) err = %v, want ErrHostPattern", tc.host, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", tc.host, err)
			}
			if got.Service != tc.wantService || got.Location != tc.wantLoc {
				t.Errorf("ParseHost(%q) = %+v, want {%q %q}", tc.host, got, tc.wantService, tc.wantLoc)
			}
		})
	}
}

func TestWWWCompoundSentinel(t *testing.T) {
	t.Parallel()

	// WWWCompoundSentinel must match what ParseHost returns for www.googleapis.com.
	got, err := ParseHost("www.googleapis.com")
	if err != nil {
		t.Fatalf("ParseHost(www.googleapis.com): %v", err)
	}
	if got.Service != WWWCompoundSentinel() {
		t.Errorf("ParseHost sentinel = %q, WWWCompoundSentinel = %q; must be equal", got.Service, WWWCompoundSentinel())
	}
}

func TestParseHostGuaranteesNonEmptyServiceOrSentinel(t *testing.T) {
	t.Parallel()

	// On success Service is either a concrete short name or the explicit
	// www-compound sentinel — never accidentally empty.
	p, err := ParseHost("storage.googleapis.com")
	if err != nil || p.Service == "" {
		t.Fatalf("expected non-empty service, got %+v err=%v", p, err)
	}
}

func TestWithService(t *testing.T) {
	t.Parallel()

	p := ParsedHost{Service: wwwCompoundSentinel, Location: "us-central1"}
	got := p.WithService("storage")
	if got.Service != "storage" || got.Location != "us-central1" {
		t.Errorf("WithService = %+v, want {storage us-central1}", got)
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parsed     ParsedHost
		claimedSvc string
		claimedLoc string
		wantErr    bool
	}{
		{name: "global match empty loc", parsed: ParsedHost{Service: "iam"}, claimedSvc: "iam", claimedLoc: ""},
		{
			name:       "global match 'global' loc",
			parsed:     ParsedHost{Service: "iam"},
			claimedSvc: "iam",
			claimedLoc: "global",
		},
		{
			name:       "global rejects regional claim",
			parsed:     ParsedHost{Service: "iam"},
			claimedSvc: "iam",
			claimedLoc: "us-central1",
			wantErr:    true,
		},
		{
			name:       "regional match",
			parsed:     ParsedHost{Service: "aiplatform", Location: "us-central1"},
			claimedSvc: "aiplatform",
			claimedLoc: "us-central1",
		},
		{
			name:       "regional loc mismatch",
			parsed:     ParsedHost{Service: "aiplatform", Location: "us-central1"},
			claimedSvc: "aiplatform",
			claimedLoc: "europe-west1",
			wantErr:    true,
		},
		{name: "service mismatch A1", parsed: ParsedHost{Service: "compute"}, claimedSvc: "iam", wantErr: true},
		{name: "empty claimed service", parsed: ParsedHost{Service: "iam"}, claimedSvc: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := Verify(tc.parsed, tc.claimedSvc, tc.claimedLoc)
			if (err != nil) != tc.wantErr {
				t.Fatalf(
					"Verify(%+v, %q, %q) err = %v, wantErr=%v",
					tc.parsed,
					tc.claimedSvc,
					tc.claimedLoc,
					err,
					tc.wantErr,
				)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrHostClaimMismatch) {
				t.Errorf("expected ErrHostClaimMismatch, got %v", err)
			}
		})
	}
}

// TestNormalizeHostPortStrip covers the port-stripping branch (L55): a host
// with a ":port" suffix that does not start with "[" must have the port removed.
func TestNormalizeHostPortStrip(t *testing.T) {
	t.Parallel()

	// compute.googleapis.com:443 is a valid host+port; after stripping the port
	// it must parse as the global compute service.
	got, err := ParseHost("compute.googleapis.com:443")
	if err != nil {
		t.Fatalf("ParseHost with port: %v", err)
	}
	if got.Service != "compute" || got.Location != "" {
		t.Errorf("got %+v, want {compute ''}", got)
	}
}

// TestRejectHostIPLiteral confirms rejectHost (via cloudauth.IsIPLiteral) denies
// bracketed-IPv6 and bare-colon IPv6 literals. These are pre-rejected by
// normalizeHost on the public ParseHost path, so rejectHost is exercised directly.
func TestRejectHostIPLiteral(t *testing.T) {
	t.Parallel()

	if !rejectHost("[::1]") {
		t.Error("rejectHost([::1]) should be true")
	}
	if !rejectHost("::1") {
		t.Error("rejectHost(::1) should be true")
	}
	if rejectHost("compute.googleapis.com") {
		t.Error("rejectHost(compute.googleapis.com) should be false")
	}
}

func TestVerify_EmptyLocationDerivedFromHost(t *testing.T) {
	t.Parallel()

	// Locational host with an omitted location claim: accepted (derived from host).
	loc := ParsedHost{Service: "compute", Location: "us-central1"} //nolint:exhaustruct // only fields under test
	if err := Verify(loc, "compute", ""); err != nil {
		t.Errorf("omitted location on locational host: got %v, want nil", err)
	}
	// A non-empty mismatched location is still rejected.
	if err := Verify(loc, "compute", "europe-west1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("mismatched location: got %v, want ErrHostClaimMismatch", err)
	}
}

// TestDispatchHostUnreachableBranches covers three dispatchHost branches that
// ParseHost's normalizeHost+rejectHost guard makes unreachable via the public
// API (L118: body==host when there is no .googleapis.com suffix even though
// rejectHost passed; L132: malformed .rep host; L152: multi-dot body with no
// matching pattern).
func TestDispatchHostUnreachableBranches(t *testing.T) {
	t.Parallel()

	// L118: body == host — supply a host that has no .googleapis.com suffix.
	// rejectHost would normally block this, but dispatchHost is internal so we
	// call it directly.
	_, err := dispatchHost("notgoogleapis.example.com")
	if !errors.Is(err, ErrHostPattern) {
		t.Errorf("dispatchHost(non-googleapis): want ErrHostPattern, got %v", err)
	}

	// L132: .rep suffix but no dot separator between svc and loc.
	_, err = dispatchHost("nodot.rep.googleapis.com")
	if !errors.Is(err, ErrHostPattern) {
		t.Errorf("dispatchHost(malformed rep): want ErrHostPattern, got %v", err)
	}

	// L152: multi-dot body that has no hyphen and is not storage/mtls/rep —
	// e.g. "a.b.googleapis.com" where body=="a.b" has a dot but no matching rule.
	_, err = dispatchHost("a.b.googleapis.com")
	if !errors.Is(err, ErrHostPattern) {
		t.Errorf("dispatchHost(multi-dot non-matching): want ErrHostPattern, got %v", err)
	}
}
