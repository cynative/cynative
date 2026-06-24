package cloudauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GetJSON GETs url and decodes JSON into T. It also returns the HTTP status code
// (0 on a transport-level error) so callers can distinguish a permanent 404/410
// from a retryable failure.
func GetJSON[T any](ctx context.Context, client *http.Client, url string) (T, int, error) {
	var zero T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return zero, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return zero, resp.StatusCode, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, resp.StatusCode, err
	}
	var out T
	if err = json.Unmarshal(body, &out); err != nil {
		return zero, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}

// GetBytes GETs url and returns the raw body. When bearer is non-empty it is
// sent as an Authorization: Bearer header (azure's authed providerOperations
// GET); an empty bearer means an anonymous GET. A non-200 status folds into the
// returned error.
func GetBytes(ctx context.Context, client *http.Client, url, bearer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	return body, err
}
