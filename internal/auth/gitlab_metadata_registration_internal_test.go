package auth

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
)

// TestGitlabOutcome_MetadataFailureKindsStillRegister pins that every way the metadata read can fail leaves a
// validated connector registered, and that api_reference then answers unavailable with that failure's reason.
func TestGitlabOutcome_MetadataFailureKindsStillRegister(t *testing.T) {
	t.Parallel()
	reasons := map[string]string{
		"timeout":         "probe failed: gitlab API probe failed: context deadline exceeded",
		"403":             "probe failed: gitlab API probe failed: status 403",
		"malformed JSON":  "parse failed: gitlab metadata probe failed: invalid metadata JSON: unexpected end",
		"missing version": "parse failed: gitlab metadata probe failed: metadata response has no version",
	}
	for name, reason := range reasons {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := stubDeps()
			var refs []string
			built := newVersionedGitLab(t, t.TempDir(), time.Now, releaseDocsFetch(new(atomic.Int32)), &refs)
			d.buildGitLab = func(GitLabHardeningConfig, string, glabCredential) (*gitlabProvider, error) {
				return built, nil
			}
			d.fetchGitLabMetadata = func(_ context.Context, p *gitlabProvider) {
				p.metadata = metadataOutcome{reason: reason}
			}
			out := d.gitlabOutcome(t.Context(), GitLabHardeningConfig{Host: "gitlab.example"}, false)
			if len(out.providers) != 1 || len(out.statuses) != 1 || !out.statuses[0].Available {
				t.Fatalf("out = %+v", out)
			}
			res := built.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdIssues"})
			want := "no GitLab OpenAPI document matches this instance: the instance's GitLab version could not " +
				"be read: " + reason
			if res.Outcome != apiref.OutcomeUnavailable || res.Reason != want {
				t.Errorf("res = %+v", res)
			}
			if len(refs) != 0 {
				t.Errorf("release docs built for %q", refs)
			}
		})
	}
}

// TestGitlabOutcome_UserFailureSkipsEvenWithGoodMetadata pins that a failed /user validation alone decides: the
// connector is skipped and the metadata is never read.
func TestGitlabOutcome_UserFailureSkipsEvenWithGoodMetadata(t *testing.T) {
	t.Parallel()
	d := stubDeps()
	d.validateGitLab = func(context.Context, *gitlabProvider) (string, error) {
		return "", errors.New("401 unauthorized")
	}
	var reads atomic.Int32
	d.fetchGitLabMetadata = func(_ context.Context, p *gitlabProvider) {
		reads.Add(1)
		p.metadata = metadataOutcome{ok: true, version: "18.11.0-ee"}
	}
	out := d.gitlabOutcome(t.Context(), GitLabHardeningConfig{Host: "gitlab.example"}, false)
	if len(out.providers) != 0 || len(out.statuses) != 1 || out.statuses[0].Available ||
		!strings.Contains(out.statuses[0].Reason, "token validation failed") {
		t.Fatalf("out = %+v", out)
	}
	if n := reads.Load(); n != 0 {
		t.Errorf("metadata read %d times after a failed /user", n)
	}
}
