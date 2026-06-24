package aws

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// httpGetBytes issues an anonymous GET and returns the response body, wrapping
// any failure in sentinel. Delegates the request/status/read mechanics to
// cloudauth.GetBytes; the three AWS fetcher shells (model-archive, iam-dataset,
// Service Reference) rely on the sentinel wrap for their [errors.Is] contracts.
func httpGetBytes(ctx context.Context, c *http.Client, url string, sentinel error) ([]byte, error) {
	body, err := cloudauth.GetBytes(ctx, c, url, "")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sentinel, err)
	}
	return body, nil
}
