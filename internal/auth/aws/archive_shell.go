package aws

import (
	"context"
	"net/http"
)

// DefaultModelArchiveURL is the gzipped tarball of the AWS-owned
// aws/api-models-aws repository (main branch).
const DefaultModelArchiveURL = "https://codeload.github.com/aws/api-models-aws/tar.gz/refs/heads/main"

// NewModelArchiveFetcher returns a fetcher that GETs the repository tarball.
// Pass as ModelArchiveConfig.Fetcher.
func NewModelArchiveFetcher(httpClient *http.Client, url string) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		return httpGetBytes(ctx, httpClient, url, ErrSmithyUnavailable)
	}
}
