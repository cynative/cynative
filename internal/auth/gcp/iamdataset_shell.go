package gcp

import (
	"context"
	"fmt"
	"net/http"
)

// DefaultIAMDatasetURL is the raw gcp/map.json from iann0036/iam-dataset.
const DefaultIAMDatasetURL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/gcp/map.json"

// NewIAMDatasetFetcher returns a fetcher that GETs url. Pass as
// IAMDatasetRegistryConfig.Fetcher.
func NewIAMDatasetFetcher(httpClient *http.Client, url string) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		return datasetHTTPGet(ctx, httpClient, url)
	}
}

// datasetHTTPGet issues a GET and returns the response body, wrapping failures
// in ErrIAMDatasetUnavailable.
func datasetHTTPGet(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrIAMDatasetUnavailable, err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch: %w", ErrIAMDatasetUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return readDatasetBody(resp)
}
