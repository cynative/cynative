package azure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
)

const (
	// SpecsRepoURL is the git remote whose tree the Azure api_reference index lists.
	SpecsRepoURL = "https://github.com/Azure/azure-rest-api-specs"
	// SpecsRawBase serves one file of that repository at a commit.
	SpecsRawBase = "https://raw.githubusercontent.com/Azure/azure-rest-api-specs"

	specsMainRef   = "refs/heads/main"
	infoRefsSuffix = "/info/refs"
	// maxRefAdvertBytes bounds the ref advertisement. It was 3,112,925 bytes on 2026-10-12 and grows with every
	// pull request, since GitHub advertises refs/pull/*.
	maxRefAdvertBytes = 32 << 20
	// maxPackBytes bounds the blobless depth-1 pack, measured at 9,764,134 bytes on 2026-10-12.
	maxPackBytes = 64 << 20
)

// requiredCapabilities are what the fetch needs from the server: a blobless, shallow pack in side-band framing.
func requiredCapabilities() []capability.Capability {
	return []capability.Capability{capability.Filter, capability.Shallow, capability.Sideband64k}
}

// bodyLimits are the response caps a fetch applies: the ref advertisement and everything else.
type bodyLimits struct{ ref, pack int64 }

// fetchPack asks repoURL for the commit main points at, depth 1, with no blobs, and returns that commit's id and
// the pack. It adds no credential of its own and follows no redirect. It sets no deadline either: the caller's
// context bounds it.
func fetchPack(ctx context.Context, client *http.Client, repoURL string) (string, []byte, error) {
	return fetchPackWithin(ctx, client, repoURL, bodyLimits{ref: maxRefAdvertBytes, pack: maxPackBytes})
}

// fetchPackWithin is fetchPack with the body caps given, so a test can reach them with small bodies.
func fetchPackWithin(ctx context.Context, client *http.Client, repoURL string, lim bodyLimits) (string, []byte, error) {
	sess, err := openUploadSession(cappedClient(client, lim), repoURL)
	if err != nil {
		return "", nil, fmt.Errorf("%w: open %s: %w", ErrSpecsRejected, repoURL, err)
	}
	adv, err := sess.AdvertisedReferencesContext(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("read the refs of %s: %w", repoURL, gitCause(err))
	}
	head, ok := adv.References[specsMainRef]
	if !ok {
		return "", nil, fmt.Errorf("%w: %s advertises no %s", ErrSpecsRejected, repoURL, specsMainRef)
	}
	for _, c := range requiredCapabilities() {
		if !adv.Capabilities.Supports(c) {
			return "", nil, fmt.Errorf("%w: %s does not offer %s", ErrSpecsRejected, repoURL, c)
		}
	}
	req := packp.NewUploadPackRequestFromCapabilities(adv.Capabilities)
	req.Wants = []plumbing.Hash{head}
	req.Depth = packp.DepthCommits(1)
	req.Filter = packp.FilterBlobNone()
	// Set fails only when a capability is given arguments it does not take; these two take none.
	_ = req.Capabilities.Set(capability.Shallow)
	_ = req.Capabilities.Set(capability.Filter)
	resp, err := sess.UploadPack(ctx, req)
	if err != nil {
		return "", nil, fmt.Errorf("fetch the pack of %s: %w", repoURL, gitCause(err))
	}
	defer func() { _ = resp.Close() }()
	pack, err := io.ReadAll(sideband.NewDemuxer(sideband.Sideband64k, resp))
	if err != nil {
		return "", nil, fmt.Errorf("read the pack of %s: %w", repoURL, err)
	}

	return head.String(), pack, nil
}

// gitCause returns the error go-git wrapped in a plumbing.UnexpectedError (plumbing/error.go:21), which has no
// Unwrap, so [errors.Is] reaches the transport's own error or the context's; any other error is returned as is.
func gitCause(err error) error {
	if ue, ok := errors.AsType[*plumbing.UnexpectedError](err); ok {
		return ue.Err
	}

	return err
}

// cappedClient returns a client that keeps c's redirect hook, cookie jar and timeout and caps every response body
// before go-git reads it.
func cappedClient(c *http.Client, lim bodyLimits) *http.Client {
	return &http.Client{
		Transport:     capTransport{base: c.Transport, refLimit: lim.ref, packLimit: lim.pack},
		CheckRedirect: c.CheckRedirect,
		Jar:           c.Jar,
		Timeout:       c.Timeout,
	}
}

// capTransport bounds each response body: the ref advertisement at refLimit, anything else at packLimit.
type capTransport struct {
	base                http.RoundTripper
	refLimit, packLimit int64
}

func (c capTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	limit := c.packLimit
	if strings.HasSuffix(req.URL.Path, infoRefsSuffix) {
		limit = c.refLimit
	}
	resp.Body = &cappedBody{body: resp.Body, limit: limit, remaining: limit}

	return resp, nil
}

// cappedBody passes at most limit bytes. Once one more byte arrives it returns no data and an error, and keeps
// returning that error, so a reader that drops an error returned with data (go-git's pkt-line scanner reads with
// [io.ReadFull], pktline/scanner.go:68) can never read past the cap.
type cappedBody struct {
	body             io.ReadCloser
	limit, remaining int64
	err              error
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.remaining == 0 {
		var probe [1]byte
		if n, err := b.body.Read(probe[:]); n == 0 {
			return 0, err
		}
		b.err = fmt.Errorf("%w: response body over %d bytes", ErrSpecsRejected, b.limit)

		return 0, b.err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)

	return n, err
}

func (b *cappedBody) Close() error { return b.body.Close() }
