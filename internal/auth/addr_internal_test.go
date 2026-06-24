package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

// addrFakeProvider is a minimal Provider that optionally implements AddrAuthorizer.
type addrFakeProvider struct {
	name        string
	addrAllowed bool
	addrErr     error
}

func (p *addrFakeProvider) Name() string                                        { return p.name }
func (p *addrFakeProvider) Description() string                                 { return "addr fake" }
func (p *addrFakeProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error { return nil }

func (p *addrFakeProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

// addrAuthProvider embeds addrFakeProvider and implements AddrAuthorizer.
type addrAuthProvider struct {
	addrFakeProvider
}

func (p *addrAuthProvider) AuthorizesAddr(
	_ context.Context, _ netip.Addr, _ json.RawMessage,
) (bool, error) {
	return p.addrAllowed, p.addrErr
}

func TestIsInternalIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"unspecified v4", "0.0.0.0", true},
		{"unspecified v6", "::", true},
		{"link-local metadata", "169.254.169.254", true},
		{"link-local v6", "fe80::1", true},
		{"rfc1918 10", "10.0.0.5", true},
		{"rfc1918 172", "172.16.3.4", true},
		{"rfc1918 192", "192.168.1.1", true},
		{"ula v6", "fc00::1", true},
		{"ula v6 fd", "fd00::1", true},
		{"ipv4-mapped metadata", "::ffff:169.254.169.254", true},
		{"ipv4-mapped rfc1918", "::ffff:10.0.0.1", true},
		{"public v4", "93.184.216.34", false},
		{"public dns v4", "8.8.8.8", false},
		{"public dns2 v4", "1.1.1.1", false},
		{"public v6", "2606:2800:220:1:248:1893:25c8:1946", false},
		{"public dns v6", "2606:4700::1111", false},
		// NAT64/6to4 embedding an internal IPv4 (metadata or RFC1918) is internal;
		// embedding a public IPv4 stays reachable for IPv6-only/DNS64 hosts.
		{"nat64 metadata", "64:ff9b::a9fe:a9fe", true},
		{"6to4 metadata", "2002:a9fe:a9fe::", true},
		{"nat64 rfc1918", "64:ff9b::a00:1", true},
		{"6to4 rfc1918", "2002:0a00:0001::", true},
		{"nat64 loopback", "64:ff9b::7f00:1", true},
		{"nat64 unspecified", "64:ff9b::", true},
		{"nat64 zoned metadata", "64:ff9b::a9fe:a9fe%eth0", true},
		// CGNAT is not internal (the shared floor allows flat 100.64.0.0/10), so a
		// NAT64-embedded CGNAT v4 stays allowed too — the documented non-goal.
		{"nat64 cgnat allowed", "64:ff9b::6440:1", false},
		{"nat64 public", "64:ff9b::8c52:7906", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ip, err := netip.ParseAddr(tc.ip)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", tc.ip, err)
			}

			if got := isInternalIP(ip); got != tc.want {
				t.Errorf("isInternalIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestIsInternalIP_InvalidIsInternal(t *testing.T) {
	t.Parallel()

	if !isInternalIP(netip.Addr{}) {
		t.Error("zero (invalid) Addr should be treated as internal")
	}
}

func TestExtractEmbeddedIPv4(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ip     string
		wantV4 string
		wantOK bool
	}{
		{"nat64 metadata", "64:ff9b::a9fe:a9fe", "169.254.169.254", true},
		{"nat64 rfc1918", "64:ff9b::a00:1", "10.0.0.1", true},
		{"nat64 public", "64:ff9b::8c52:7906", "140.82.121.6", true},
		{"6to4 rfc1918", "2002:0a00:0001::", "10.0.0.1", true},
		{"6to4 metadata", "2002:a9fe:a9fe::", "169.254.169.254", true},
		{"zoned nat64 metadata", "64:ff9b::a9fe:a9fe%eth0", "169.254.169.254", true},
		{"non-embedding gua v6", "2606:50c0::153", "", false},
		{"ula v6", "fc00::1", "", false},
		{"ipv4 input", "10.0.0.1", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := extractEmbeddedIPv4(netip.MustParseAddr(tc.ip))
			if ok != tc.wantOK {
				t.Fatalf("extractEmbeddedIPv4(%s) ok = %v, want %v", tc.ip, ok, tc.wantOK)
			}

			if ok && got != netip.MustParseAddr(tc.wantV4) {
				t.Errorf("extractEmbeddedIPv4(%s) = %s, want %s", tc.ip, got, tc.wantV4)
			}
		})
	}
}

func TestAuthorizeAddr_DefaultDenyInternal(t *testing.T) {
	t.Parallel()

	providers := []Provider{&addrFakeProvider{name: "cloud"}}
	ip := netip.MustParseAddr("169.254.169.254")

	err := AuthorizeAddr(context.Background(), "cloud", ip, providers, nil)
	if !errors.Is(err, ErrAddrNotAuthorized) {
		t.Fatalf("expected ErrAddrNotAuthorized for internal IP, got %v", err)
	}
}

func TestAuthorizeAddr_DefaultDenyIPv4MappedInternal(t *testing.T) {
	t.Parallel()

	providers := []Provider{&addrFakeProvider{name: "cloud"}}
	ip := netip.MustParseAddr("::ffff:169.254.169.254")

	err := AuthorizeAddr(context.Background(), "cloud", ip, providers, nil)
	if !errors.Is(err, ErrAddrNotAuthorized) {
		t.Fatalf("expected ErrAddrNotAuthorized for IPv4-mapped internal IP, got %v", err)
	}
}

func TestAuthorizeAddr_DefaultDenyInvalid(t *testing.T) {
	t.Parallel()

	providers := []Provider{&addrFakeProvider{name: "cloud"}}

	err := AuthorizeAddr(context.Background(), "cloud", netip.Addr{}, providers, nil)
	if !errors.Is(err, ErrAddrNotAuthorized) {
		t.Fatalf("expected ErrAddrNotAuthorized for invalid IP, got %v", err)
	}
}

func TestAuthorizeAddr_DefaultAllowPublic(t *testing.T) {
	t.Parallel()

	providers := []Provider{&addrFakeProvider{name: "cloud"}}
	ip := netip.MustParseAddr("93.184.216.34")

	if err := AuthorizeAddr(context.Background(), "cloud", ip, providers, nil); err != nil {
		t.Fatalf("expected public IP allowed by default, got %v", err)
	}
}

func TestAuthorizeAddr_ProviderAllowsInternal(t *testing.T) {
	t.Parallel()

	p := &addrAuthProvider{addrFakeProvider: addrFakeProvider{name: "k8s", addrAllowed: true}}
	ip := netip.MustParseAddr("10.0.0.5")

	if err := AuthorizeAddr(context.Background(), "k8s", ip, []Provider{p}, nil); err != nil {
		t.Fatalf("provider that allows should override default deny, got %v", err)
	}
}

func TestAuthorizeAddr_ProviderDeniesPublic(t *testing.T) {
	t.Parallel()

	p := &addrAuthProvider{addrFakeProvider: addrFakeProvider{name: "k8s", addrAllowed: false}}
	ip := netip.MustParseAddr("93.184.216.34")

	err := AuthorizeAddr(context.Background(), "k8s", ip, []Provider{p}, nil)
	if !errors.Is(err, ErrAddrNotAuthorized) {
		t.Fatalf("provider deny should wrap ErrAddrNotAuthorized, got %v", err)
	}
}

func TestAuthorizeAddr_ProviderError(t *testing.T) {
	t.Parallel()

	boom := errors.New("addr boom")
	p := &addrAuthProvider{addrFakeProvider: addrFakeProvider{name: "k8s", addrErr: boom}}
	ip := netip.MustParseAddr("10.0.0.5")

	err := AuthorizeAddr(context.Background(), "k8s", ip, []Provider{p}, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped provider error, got %v", err)
	}
}

func TestAuthorizeAddr_UnknownProvider(t *testing.T) {
	t.Parallel()

	ip := netip.MustParseAddr("93.184.216.34")

	err := AuthorizeAddr(context.Background(), "nope", ip, nil, nil)
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("expected ErrUnknownProvider, got %v", err)
	}
}

func TestFloorForbidden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"unspecified v4", "0.0.0.0", true},
		{"unspecified v6", "::", true},
		{"link-local metadata", "169.254.169.254", true},
		{"link-local v6", "fe80::1", true},
		{"ipv4-mapped metadata", "::ffff:169.254.169.254", true},
		{"link-local multicast v4", "224.0.0.1", true},
		{"interface-local multicast v6", "ff01::1", true},
		// Every cloud's IPv6 metadata service lives in ULA space (fc00::/7), all
		// denied wholesale — no managed cluster endpoint is ever ULA.
		{"aws ipv6 imds", "fd00:ec2::254", true},
		{"aws ipv6 ntp", "fd00:ec2::123", true},
		{"aws ipv6 pod-identity", "fd00:ec2::23", true},
		{"gcp ipv6 metadata", "fd20:ce::254", true},
		{"oci ipv6 metadata", "fd00:c1::a9fe:a9fe", true},
		{"scaleway ipv6 metadata", "fd00:42::42", true},
		{"alibaba ipv6 metadata", "fd00:100::100:200", true},
		{"ula v6 generic", "fc00::1", true},
		{"ula v6 fd", "fd12:3456::1", true},
		{"azure wireserver", "168.63.129.16", true},
		{"alibaba ecs metadata", "100.100.100.200", true},
		// RFC1918 IPv4 and global-unicast IPv6 are NOT floor-forbidden (legitimate
		// cluster endpoints); the exact-IP pin constrains them.
		{"rfc1918 10", "10.0.0.5", false},
		{"rfc1918 172", "172.16.3.4", false},
		{"rfc1918 192", "192.168.1.1", false},
		{"gua v6 aws-style", "2600:1f00::1", false},
		{"gua v6 public", "2606:4700::1111", false},
		// CGNAT shared space is allowed except the exact Alibaba metadata address —
		// legitimate clusters (e.g. EKS pod CIDRs) use 100.64.0.0/10.
		{"cgnat shared not metadata", "100.64.0.1", false},
		{"cgnat near metadata", "100.100.100.201", false},
		{"public v4", "93.184.216.34", false},
		// NAT64/6to4 embedding an internal IPv4 is floor-forbidden ONLY when the
		// embedded v4 is itself floor-forbidden (metadata); an embedded RFC1918 v4
		// is NOT floor-forbidden (it reaches the per-provider exact-IP pin), and an
		// embedded public v4 stays allowed (IPv6-only/DNS64 reachability).
		{"nat64 metadata", "64:ff9b::a9fe:a9fe", true},
		{"6to4 metadata", "2002:a9fe:a9fe::", true},
		{"nat64 loopback", "64:ff9b::7f00:1", true},
		{"nat64 unspecified", "64:ff9b::", true},
		{"nat64 zoned metadata", "64:ff9b::a9fe:a9fe%eth0", true},
		{"nat64 rfc1918 not floor", "64:ff9b::a00:1", false},
		{"6to4 rfc1918 not floor", "2002:0a00:0001::", false},
		{"nat64 cgnat not floor", "64:ff9b::6440:1", false},
		{"nat64 public", "64:ff9b::8c52:7906", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ip, err := netip.ParseAddr(tc.ip)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", tc.ip, err)
			}

			if got := floorForbidden(ip); got != tc.want {
				t.Errorf("floorForbidden(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestFloorForbidden_InvalidIsForbidden(t *testing.T) {
	t.Parallel()

	if !floorForbidden(netip.Addr{}) {
		t.Error("zero (invalid) Addr must be floor-forbidden")
	}
}
