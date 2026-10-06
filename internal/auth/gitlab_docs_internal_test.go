package auth

import (
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

func TestGitLabRefusedInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		loc  apiref.Location
		name string
		want bool
	}{
		{apiref.LocationQuery, "sudo", true},
		{apiref.LocationQuery, "SUDO", true},
		{apiref.LocationQuery, "token", true},
		{apiref.LocationQuery, "token[]", true},
		{apiref.LocationQuery, "private_token", true},
		{apiref.LocationQuery, "Feed_Token", true},
		{apiref.LocationQuery, "rss_token[x]", true},
		{apiref.LocationQuery, "page", false},
		{apiref.LocationHeader, "Sudo", true},
		{apiref.LocationHeader, "sudo", true},
		{apiref.LocationHeader, "Private-Token", true},
		{apiref.LocationHeader, "Private_Token", true},
		{apiref.LocationHeader, "job-token", true},
		{apiref.LocationHeader, "Cookie", true},
		{apiref.LocationHeader, "Authorization", true},
		{apiref.LocationHeader, "X-Request-Id", false},
		{apiref.LocationBody, "token", true},
		{apiref.LocationBody, "JOB_TOKEN", true},
		{apiref.LocationBody, "access_token[]", true},
		{apiref.LocationBody, "title", false},
		{apiref.LocationPath, "token", false},
	}
	for _, tc := range cases {
		if got := gitlabRefusedInput(tc.loc, tc.name); got != tc.want {
			t.Errorf("%s %q: got %v, want %v", tc.loc, tc.name, got, tc.want)
		}
	}
}

// TestGitLabRefusedInput_CoversEveryListedName ties the docs-side check to the gate's lists: a name added to a
// list is refused in the docs with no second edit.
func TestGitLabRefusedInput_CoversEveryListedName(t *testing.T) {
	t.Parallel()
	for _, h := range credentialHeaders {
		if !gitlabRefusedInput(apiref.LocationHeader, h) {
			t.Errorf("header %q not refused", h)
		}
	}
	for _, p := range credentialParams {
		if !gitlabRefusedInput(apiref.LocationQuery, p) {
			t.Errorf("query %q not refused", p)
		}
	}
	for _, p := range gitlabBodyCredentialParams {
		if !gitlabRefusedInput(apiref.LocationBody, p) {
			t.Errorf("body %q not refused", p)
		}
	}
}
