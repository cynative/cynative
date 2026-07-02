package gcp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// DefaultIAMDatasetURL is the raw gcp/map.json from iann0036/iam-dataset.
const DefaultIAMDatasetURL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/gcp/map.json"

// NewIAMDatasetFetcher returns a fetcher that GETs url, wrapping any failure in
// ErrIAMDatasetUnavailable. Delegates the request/status/read mechanics to
// cloudauth.GetBytes. Pass as IAMDatasetRegistryConfig.Fetcher.
func NewIAMDatasetFetcher(httpClient *http.Client, url string) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		body, err := cloudauth.GetBytes(ctx, httpClient, url, "")
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIAMDatasetUnavailable, err)
		}
		return body, nil
	}
}
