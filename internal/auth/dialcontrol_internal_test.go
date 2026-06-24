package auth

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestContains(t *testing.T) {
	t.Parallel()

	set := []netip.Addr{
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("2606:4700::1111"),
	}

	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"present v4", "10.0.0.5", true},
		{"present v6", "2606:4700::1111", true},
		{"absent v4", "10.0.0.6", false},
		{"ipv4-mapped of present", "::ffff:10.0.0.5", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := contains(set, netip.MustParseAddr(tc.ip)); got != tc.want {
				t.Errorf("contains(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestDialControl(t *testing.T) {
	t.Parallel()

	allow := func(_ context.Context, _ netip.Addr) (bool, error) { return true, nil }
	deny := func(_ context.Context, _ netip.Addr) (bool, error) { return false, nil }
	boom := errors.New("authorize boom")
	errf := func(_ context.Context, _ netip.Addr) (bool, error) { return false, boom }

	t.Run("allows when authorize allows", func(t *testing.T) {
		t.Parallel()

		ctl := dialControl(allow)
		if err := ctl(context.Background(), "tcp", "93.184.216.34:443", nil); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
	})

	t.Run("authorize=false denies with ErrAddrNotAuthorized", func(t *testing.T) {
		t.Parallel()

		ctl := dialControl(deny)
		err := ctl(context.Background(), "tcp", "93.184.216.34:443", nil)
		if !errors.Is(err, ErrAddrNotAuthorized) {
			t.Fatalf("authorize=false must deny, got %v", err)
		}
	})

	t.Run("authorize error propagates", func(t *testing.T) {
		t.Parallel()

		ctl := dialControl(errf)
		err := ctl(context.Background(), "tcp", "93.184.216.34:443", nil)
		if !errors.Is(err, boom) {
			t.Fatalf("authorize error must propagate, got %v", err)
		}
	})

	t.Run("bad address errors", func(t *testing.T) {
		t.Parallel()

		ctl := dialControl(allow)
		if err := ctl(context.Background(), "tcp", "not-an-address", nil); err == nil {
			t.Fatal("malformed dial address must error")
		}
	})

	t.Run("non-IP host errors", func(t *testing.T) {
		t.Parallel()

		ctl := dialControl(allow)
		if err := ctl(context.Background(), "tcp", "example.com:443", nil); err == nil {
			t.Fatal("non-IP dial host must error")
		}
	})
}
