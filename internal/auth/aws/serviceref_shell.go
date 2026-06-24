package aws

import (
	"context"
	"net/http"
	"strings"
)

// DefaultServiceRefTemplate is the per-service Service Reference URL. Unlike
// the Smithy mirror, it needs no API version.
const DefaultServiceRefTemplate = "https://servicereference.us-east-1.amazonaws.com/v1/{service}/{service}.json"

// NewServiceRefFetcher returns a fetcher resolving {service} in template and
// issuing an HTTPS GET. Pass as ServiceRefRegistryConfig.Fetcher.
func NewServiceRefFetcher(
	httpClient *http.Client, template string,
) func(ctx context.Context, service string) ([]byte, error) {
	return func(ctx context.Context, service string) ([]byte, error) {
		url := strings.ReplaceAll(template, "{service}", service)
		return httpGetBytes(ctx, httpClient, url, ErrServiceRefUnavailable)
	}
}
