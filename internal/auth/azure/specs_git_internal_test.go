package azure

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// errTransport is the sentinel a fake RoundTripper returns for a transport failure.
var errTransport = errors.New("transport down")

func clientFor(rt http.RoundTripper) *http.Client { return &http.Client{Transport: rt} }

// parseWantLineCaps extracts the capability tokens from the first pkt-line of an upload-pack request.
func parseWantLineCaps(body string) []string {
	if len(body) < 4 {
		return nil
	}
	// Read the pkt-line length.
	n := 0
	for _, c := range body[:4] {
		n = n<<4 | strings.IndexByte("0123456789abcdef", byte(c))
	}
	if n < 4 || n > len(body) {
		return nil
	}
	line := body[4:n]
	// The want line is "want <hash> <cap1> <cap2> ... <capN>\n".
	parts := strings.Fields(line)
	if len(parts) < 3 || parts[0] != "want" {
		return nil
	}

	return parts[2:] // Skip "want" and the hash.
}

// TestFetchPack_FetchesMainShallowAndBlobless pins the request the fetch sends (want main, depth 1, filter
// blob:none, with the shallow, filter and side-band-64k capabilities) and that it returns main's SHA and the pack
// exactly as served on side-band 1, the progress frame dropped.
func TestFetchPack_FetchesMainShallowAndBlobless(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	caps := append(fullCaps(), capability.ThinPack)
	srv := newGitServer(advertisement(t, commit, caps...), uploadResponse(t, commit, pack))
	sha, got, err := fetchPack(t.Context(), clientFor(srv), testRepoURL)
	if err != nil {
		t.Fatalf("fetchPack: %v", err)
	}
	if sha != commit.String() || !bytes.Equal(got, pack) {
		t.Fatalf("sha %s (want %s), pack %d bytes (want %d)", sha, commit, len(got), len(pack))
	}
	body := srv.uploadBody()
	wantCaps := parseWantLineCaps(body)
	for _, want := range []string{"shallow", "filter", "side-band-64k"} {
		if !slices.Contains(wantCaps, want) {
			t.Errorf("want-line capabilities lack %q: %v\nfull body:\n%s", want, wantCaps, body)
		}
	}
	for _, want := range []string{"want " + commit.String(), "deepen 1", "filter blob:none", "done"} {
		if !strings.Contains(body, want) {
			t.Errorf("upload-pack request lacks %q:\n%s", want, body)
		}
	}
	if slices.Contains(wantCaps, "thin-pack") {
		t.Errorf("want-line asks for a thin pack: %v\nfull body:\n%s", wantCaps, body)
	}
}

// TestFetchPack_RefusesAServerMissingACapability pins that each required capability is checked before any pack
// is requested.
func TestFetchPack_RefusesAServerMissingACapability(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	for _, missing := range []capability.Capability{capability.Filter, capability.Shallow, capability.Sideband64k} {
		t.Run(missing.String(), func(t *testing.T) {
			t.Parallel()
			var caps []capability.Capability
			for _, c := range fullCaps() {
				if c != missing {
					caps = append(caps, c)
				}
			}
			srv := newGitServer(advertisement(t, commit, caps...), uploadResponse(t, commit, pack))
			_, _, err := fetchPack(t.Context(), clientFor(srv), testRepoURL)
			if !errors.Is(err, ErrSpecsRejected) || !strings.Contains(err.Error(), missing.String()) {
				t.Fatalf("err = %v, want ErrSpecsRejected naming %s", err, missing)
			}
			if srv.uploadBody() != "" {
				t.Errorf("a pack was requested from a server without %s", missing)
			}
		})
	}
}

// TestFetchPack_Failures pins every failure before and during the fetch.
func TestFetchPack_Failures(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	good := func(t *testing.T) *gitServer {
		t.Helper()

		return newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
	}
	errorFrame := func(t *testing.T) []byte {
		t.Helper()
		resp := uploadResponse(t, commit, nil)
		var buf bytes.Buffer
		buf.Write(resp[:len(resp)-len("0000")])
		if _, err := sideband.NewMuxer(sideband.Sideband64k, &buf).WriteChannel(sideband.ErrorMessage,
			[]byte("boom")); err != nil {
			t.Fatalf("error frame: %v", err)
		}

		return buf.Bytes()
	}
	cases := map[string]struct {
		srv  func(t *testing.T) *gitServer
		url  string
		want func(error) bool
	}{
		"bad url": {good, "http://[::1", func(err error) bool { return errors.Is(err, ErrSpecsRejected) }},
		"refs transport error": {func(t *testing.T) *gitServer {
			t.Helper()
			s := good(t)
			s.advErr = errTransport

			return s
		}, testRepoURL, func(err error) bool { return errors.Is(err, errTransport) }},
		"refs not found": {func(t *testing.T) *gitServer {
			t.Helper()
			s := good(t)
			s.advStatus = http.StatusNotFound

			return s
		}, testRepoURL, func(err error) bool { return errors.Is(err, transport.ErrRepositoryNotFound) }},
		"redirect refused": {func(t *testing.T) *gitServer {
			t.Helper()
			s := good(t)
			s.location = "https://elsewhere.example/repo/info/refs?service=git-upload-pack"

			return s
		}, testRepoURL, func(err error) bool { return err != nil && strings.Contains(err.Error(), "redirect") }},
		"no main": {func(t *testing.T) *gitServer {
			t.Helper()
			adv := bytes.ReplaceAll(advertisement(t, commit, fullCaps()...), []byte("refs/heads/main"),
				[]byte("refs/heads/mainx"))

			return newGitServer(fixPktLengths(t, adv), uploadResponse(t, commit, pack))
		}, testRepoURL, func(err error) bool { return errors.Is(err, ErrSpecsRejected) }},
		"upload transport error": {func(t *testing.T) *gitServer {
			t.Helper()
			s := good(t)
			s.upErr = errTransport

			return s
		}, testRepoURL, func(err error) bool { return errors.Is(err, errTransport) }},
		"upload server error": {func(t *testing.T) *gitServer {
			t.Helper()
			s := good(t)
			s.respStatus = http.StatusInternalServerError

			return s
		}, testRepoURL, func(err error) bool { return err != nil }},
		"error frame": {func(t *testing.T) *gitServer {
			t.Helper()

			return newGitServer(advertisement(t, commit, fullCaps()...), errorFrame(t))
		}, testRepoURL, func(err error) bool { return err != nil && strings.Contains(err.Error(), "boom") }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := fetchPack(t.Context(), clientFor(tc.srv(t)), tc.url)
			if !tc.want(err) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// TestFetchPack_HonoursTheContext pins that a context cancelled before the fetch, or while the upload-pack request
// is in flight, stops the fetch with the context's error reachable through [errors.Is]. The second case crosses
// go-git's plumbing.UnexpectedError, which has no Unwrap.
func TestFetchPack_HonoursTheContext(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	t.Run("before", func(t *testing.T) {
		t.Parallel()
		srv := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, _, err := fetchPack(ctx, clientFor(srv), testRepoURL); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if srv.uploadBody() != "" {
			t.Error("a pack was requested after the context was cancelled")
		}
	})
	t.Run("during upload", func(t *testing.T) {
		t.Parallel()
		srv := newGitServer(advertisement(t, commit, fullCaps()...), uploadResponse(t, commit, pack))
		ctx, cancel := context.WithCancel(t.Context())
		srv.onUpload = cancel
		if _, _, err := fetchPack(ctx, clientFor(srv), testRepoURL); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

// TestFetchPackWithin_EnforcesTheCapsThroughGoGit pins both caps end to end: a well-formed advertisement over the
// ref cap, decoded by go-git's [io.ReadFull] scanner, and a pack over the pack cap each fail with ErrSpecsRejected,
// and bodies exactly at the caps pass.
func TestFetchPackWithin_EnforcesTheCapsThroughGoGit(t *testing.T) {
	t.Parallel()
	commit, pack := smallRepo(t)
	adv := advertisement(t, commit, fullCaps()...)
	resp := uploadResponse(t, commit, pack)
	t.Run("ref advertisement", func(t *testing.T) {
		t.Parallel()
		srv := newGitServer(adv, resp)
		lim := bodyLimits{ref: int64(len(adv) - 1), pack: maxPackBytes}
		_, _, err := fetchPackWithin(t.Context(), clientFor(srv), testRepoURL, lim)
		if !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("err = %v, want ErrSpecsRejected", err)
		}
		if srv.uploadBody() != "" {
			t.Error("a pack was requested after the advertisement passed its cap")
		}
	})
	t.Run("pack", func(t *testing.T) {
		t.Parallel()
		lim := bodyLimits{ref: maxRefAdvertBytes, pack: int64(len(resp) - 1)}
		_, _, err := fetchPackWithin(t.Context(), clientFor(newGitServer(adv, resp)), testRepoURL, lim)
		if !errors.Is(err, ErrSpecsRejected) {
			t.Fatalf("err = %v, want ErrSpecsRejected", err)
		}
	})
	t.Run("at the caps", func(t *testing.T) {
		t.Parallel()
		lim := bodyLimits{ref: int64(len(adv)), pack: int64(len(resp))}
		_, _, err := fetchPackWithin(t.Context(), clientFor(newGitServer(adv, resp)), testRepoURL, lim)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestGitCause pins that the cause inside go-git's UnexpectedError is returned and any other error passes through.
func TestGitCause(t *testing.T) {
	t.Parallel()
	if got := gitCause(plumbing.NewUnexpectedError(errTransport)); got != errTransport { //nolint:errorlint // identity.
		t.Errorf("gitCause(UnexpectedError) = %v", got)
	}
	if got := gitCause(errTransport); got != errTransport { //nolint:errorlint // identity is the property.
		t.Errorf("gitCause(plain) = %v", got)
	}
}

// TestCappedBody pins each read path: a short buffer, a buffer longer than what remains, a body exactly at the cap
// ending in EOF, and a body over the cap whose first extra byte yields no data and a latched error that
// [io.ReadFull] cannot drop.
func TestCappedBody(t *testing.T) {
	t.Parallel()
	body := func(n, limit int) *cappedBody {
		return &cappedBody{
			body:  io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), n))),
			limit: int64(limit), remaining: int64(limit),
		}
	}
	b := body(4, 4)
	buf := make([]byte, 1)
	if n, err := b.Read(buf); n != 1 || err != nil {
		t.Fatalf("short read = %d, %v", n, err)
	}
	big := make([]byte, 16)
	if n, err := b.Read(big); n != 3 || err != nil {
		t.Fatalf("trimmed read = %d, %v, want 3 bytes", n, err)
	}
	if n, err := b.Read(big); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("at the cap = %d, %v, want EOF", n, err)
	}
	over := body(5, 4)
	if _, err := io.ReadFull(over, make([]byte, 4)); err != nil {
		t.Fatalf("the first 4 bytes: %v", err)
	}
	if n, err := io.ReadFull(over, buf); n != 0 || !errors.Is(err, ErrSpecsRejected) {
		t.Fatalf("over the cap = %d, %v, want 0 and ErrSpecsRejected", n, err)
	}
	if n, err := over.Read(big); n != 0 || !errors.Is(err, ErrSpecsRejected) {
		t.Fatalf("after the cap = %d, %v, want the latched error", n, err)
	}
}

// TestCapTransport_BoundsEachBody pins the two body caps: info/refs gets the advertisement cap, everything else
// the pack cap, and a body at the cap is read whole.
func TestCapTransport_BoundsEachBody(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte("x"), 8)
	rt := capTransport{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResponse(r, http.StatusOK, body), nil
	}), refLimit: 7, packLimit: 8}
	read := func(path string) error {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://git.example"+path, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)

		return err
	}
	if err := read("/repo/info/refs"); !errors.Is(err, ErrSpecsRejected) {
		t.Errorf("refs over its cap: err = %v, want ErrSpecsRejected", err)
	}
	if err := read("/repo/git-upload-pack"); err != nil {
		t.Errorf("pack at its cap: err = %v", err)
	}
	failing := capTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errTransport
	})}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://git.example/x", nil)
	if _, err := failing.RoundTrip(req); !errors.Is(err, errTransport) {
		t.Errorf("transport error: err = %v", err)
	}
}

// TestCappedClient_KeepsTheCallersPolicy pins that the capped client keeps the redirect hook and timeout it wraps.
func TestCappedClient_KeepsTheCallersPolicy(t *testing.T) {
	t.Parallel()
	refuse := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := cappedClient(
		&http.Client{Transport: http.DefaultTransport, CheckRedirect: refuse, Timeout: 7},
		bodyLimits{ref: maxRefAdvertBytes, pack: maxPackBytes},
	)
	ct, ok := c.Transport.(capTransport)
	if !ok || ct.refLimit != maxRefAdvertBytes || ct.packLimit != maxPackBytes || c.Timeout != 7 ||
		c.CheckRedirect == nil {
		t.Fatalf("capped client = %+v", c)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fixPktLengths rewrites every pkt-line length prefix after a byte substitution changed payload lengths.
func fixPktLengths(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	for len(b) > 0 {
		n := 0
		for _, c := range b[:4] {
			n = n<<4 | strings.IndexByte("0123456789abcdef", c)
		}
		if n == 0 {
			out.WriteString("0000")
			b = b[4:]

			continue
		}
		end := bytes.IndexByte(b[4:], '\n') + 5
		payload := b[4:end]
		out.WriteString(pktHex(len(payload) + 4))
		out.Write(payload)
		b = b[end:]
	}

	return out.Bytes()
}

func pktHex(n int) string {
	const digits = "0123456789abcdef"

	return string([]byte{digits[n>>12&15], digits[n>>8&15], digits[n>>4&15], digits[n&15]})
}
