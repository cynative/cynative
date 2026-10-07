package gcp

import (
	"context"
	"fmt"
	"net/http"
)

// NewDocsFetcher returns the api_reference download: an anonymous GET through client whose body is capped at
// maxDocumentBytes. It never attaches a credential.
func NewDocsFetcher(client *http.Client) func(ctx context.Context, url string) ([]byte, error) {
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
		}
		return readCapped(resp.Body, maxDocumentBytes)
	}
}
