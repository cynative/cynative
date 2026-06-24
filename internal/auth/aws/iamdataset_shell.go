package aws

import (
	"context"
	"net/http"
)

// DefaultIAMDatasetURL is the raw map.json from iann0036/iam-dataset.
const DefaultIAMDatasetURL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/map.json"

// NewIAMDatasetFetcher returns a fetcher that GETs url. Pass as
// IAMDatasetRegistryConfig.Fetcher.
func NewIAMDatasetFetcher(httpClient *http.Client, url string) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		return httpGetBytes(ctx, httpClient, url, ErrIAMDatasetUnavailable)
	}
}
