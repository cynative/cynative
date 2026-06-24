package azure

import (
	"errors"
	"testing"
)

func TestParseHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		host     string
		wantHost string // normalized host on the accept path.
		wantErr  error  // nil on accept; a sentinel on reject.
	}{
		// control-plane candidate accepts (Cloud filled later by the catalog).
		{name: "arm public", host: "management.azure.com", wantHost: "management.azure.com"},
		{name: "arm usgov", host: "management.usgovcloudapi.net", wantHost: "management.usgovcloudapi.net"},
		{name: "arm china", host: "management.chinacloudapi.cn", wantHost: "management.chinacloudapi.cn"},
		{name: "uppercase normalized", host: "Management.Azure.Com", wantHost: "management.azure.com"},
		{name: "trailing dot stripped", host: "management.azure.com.", wantHost: "management.azure.com"},
		{name: "port stripped", host: "management.azure.com:443", wantHost: "management.azure.com"},

		// data-plane → ErrDataPlaneNotSupported (A4/A5).
		{name: "key vault data-plane", host: "myvault.vault.azure.net", wantErr: ErrDataPlaneNotSupported},
		{name: "blob data-plane", host: "acct.blob.core.windows.net", wantErr: ErrDataPlaneNotSupported},
		{name: "queue data-plane", host: "acct.queue.core.windows.net", wantErr: ErrDataPlaneNotSupported},
		{name: "sql data-plane", host: "srv.database.windows.net", wantErr: ErrDataPlaneNotSupported},
		{name: "managed hsm data-plane", host: "h.managedhsm.azure.net", wantErr: ErrDataPlaneNotSupported},

		// graph → ErrGraphNotSupported (A6).
		{name: "graph", host: "graph.microsoft.com", wantErr: ErrGraphNotSupported},

		// SSRF / spoof / private → ErrHostPattern.
		{name: "imds ipv4", host: "169.254.169.254", wantErr: ErrHostPattern},                 // A3
		{name: "imds ipv4-mapped", host: "[::ffff:169.254.169.254]", wantErr: ErrHostPattern}, // A3
		{name: "metadata host", host: "metadata.azure.com", wantErr: ErrHostPattern},          // A3
		{name: "localhost", host: "localhost", wantErr: ErrHostPattern},                       // A3
		{name: "dot-local", host: "host.local", wantErr: ErrHostPattern},
		{name: "rfc1918", host: "10.0.0.5", wantErr: ErrHostPattern},
		{name: "ipv6 loopback", host: "[::1]", wantErr: ErrHostPattern},
		{name: "link-local v6", host: "[fe80::1]", wantErr: ErrHostPattern},
		{name: "privatelink by label", host: "myvault.privatelink.vaultcore.azure.net", wantErr: ErrHostPattern}, // A7
		{name: "suffix spoof", host: "management.azure.com.evil.com", wantErr: ErrHostPattern},                   // A2
		{name: "userinfo", host: "foo@management.azure.com", wantErr: ErrHostPattern},                            // A10
		{
			name:    "idn homoglyph",
			host:    "mаnagement.azure.com",
			wantErr: ErrHostPattern,
		}, // A10 (Cyrillic 'а')
		{name: "empty", host: "", wantErr: ErrHostPattern},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseHost(tc.host)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseHost(%q) err = %v, want %v", tc.host, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", tc.host, err)
			}
			if got.Host != tc.wantHost {
				t.Errorf("ParseHost(%q).Host = %q, want %q", tc.host, got.Host, tc.wantHost)
			}
			if got.Cloud != "" {
				t.Errorf("ParseHost(%q).Cloud = %q, want empty (catalog fills it)", tc.host, got.Cloud)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		parsed       ParsedHost
		claimedCloud string
		wantErr      bool
	}{
		{
			name:         "empty claim accepts",
			parsed:       ParsedHost{Host: "management.azure.com", Cloud: "AzureCloud"},
			claimedCloud: "",
		},
		{
			name:         "match",
			parsed:       ParsedHost{Host: "management.azure.com", Cloud: "AzureCloud"},
			claimedCloud: "AzureCloud",
		},
		{
			name:         "match case-insensitive",
			parsed:       ParsedHost{Host: "management.azure.com", Cloud: "AzureCloud"},
			claimedCloud: "azurecloud",
		},
		{
			name:         "cloud mismatch",
			parsed:       ParsedHost{Host: "management.azure.com", Cloud: "AzureCloud"},
			claimedCloud: "AzureChinaCloud",
			wantErr:      true,
		},
		{
			name:         "unresolved cloud rejects non-empty claim",
			parsed:       ParsedHost{Host: "management.azure.com", Cloud: ""},
			claimedCloud: "AzureCloud",
			wantErr:      true,
		},
		{
			name:         "AzureChinaCloud claim matches canonical AzureChinaCloud",
			parsed:       ParsedHost{Host: "management.chinacloudapi.cn", Cloud: "AzureChinaCloud"},
			claimedCloud: "AzureChinaCloud",
		},
		{
			name:         "AzureChinaCloud rejects AzureCloud claim",
			parsed:       ParsedHost{Host: "management.chinacloudapi.cn", Cloud: "AzureChinaCloud"},
			claimedCloud: "AzureCloud",
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := Verify(tc.parsed, tc.claimedCloud)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Verify(%+v, %q) err = %v, wantErr=%v", tc.parsed, tc.claimedCloud, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrHostClaimMismatch) {
				t.Errorf("expected ErrHostClaimMismatch, got %v", err)
			}
		})
	}
}

func TestWithCloud(t *testing.T) {
	t.Parallel()

	p := ParsedHost{Host: "management.azure.com"}
	got := p.WithCloud("AzureCloud")
	if got.Cloud != "AzureCloud" || got.Host != "management.azure.com" {
		t.Errorf("WithCloud = %+v, want {management.azure.com AzureCloud}", got)
	}
}

// TestRejectHostIPLiteral confirms rejectHost (via cloudauth.IsIPLiteral) denies
// bracketed-IPv6 and bare-colon IPv6 literals. normalizeHost pre-rejects these on
// the public ParseHost path, so rejectHost is exercised directly.
func TestRejectHostIPLiteral(t *testing.T) {
	t.Parallel()

	if !rejectHost("[::1]") {
		t.Error("rejectHost([::1]) should be true")
	}
	if !rejectHost("::1") {
		t.Error("rejectHost(::1) should be true")
	}
	if rejectHost("management.azure.com") {
		t.Error("rejectHost(management.azure.com) should be false")
	}
}

// TestClassifyHostUnreachableBranches exercises the classify branch reached only
// when rejectHost has already passed (a defensive fall-through). classifyHost is
// internal, so we call it directly with a host that is neither data-plane, graph,
// nor a known ARM host.
func TestClassifyHostUnreachableBranches(t *testing.T) {
	t.Parallel()

	_, err := classifyHost("management.azure.com.evil.com")
	if !errors.Is(err, ErrHostPattern) {
		t.Errorf("classifyHost(spoof): want ErrHostPattern, got %v", err)
	}
}
