package auth

import (
	"context"
	"testing"
)

func TestGitlabOutcome_BelowFloor(t *testing.T) {
	t.Parallel()

	d := stubDeps()
	// Override metadata fetch to return a below-floor version.
	d.fetchGitLabMetadata = func(context.Context, *gitlabProvider) metadataOutcome {
		return metadataOutcome{ok: true, version: "18.8.0-ee"}
	}

	out := d.gitlabOutcome(context.Background(), GitLabHardeningConfig{}, false)

	if len(out.providers) != 0 {
		t.Errorf("gitlabOutcome() with below-floor version should skip, got %d providers", len(out.providers))
	}
	if len(out.statuses) != 1 {
		t.Fatalf("gitlabOutcome() statuses = %d, want 1", len(out.statuses))
	}
	status := out.statuses[0]
	if status.Available {
		t.Errorf("gitlabOutcome() available = true, want false")
	}
	if status.Reason == "" {
		t.Errorf("gitlabOutcome() reason should mention version requirement")
	}
}

func TestGitlabOutcome_MetadataFailureDoesNotPreventRegistration(t *testing.T) {
	t.Parallel()

	d := stubDeps()
	// Override metadata fetch to fail.
	d.fetchGitLabMetadata = func(context.Context, *gitlabProvider) metadataOutcome {
		return metadataOutcome{ok: false, reason: "probe failed"}
	}

	out := d.gitlabOutcome(context.Background(), GitLabHardeningConfig{}, false)

	// Should still register despite metadata failure.
	if len(out.providers) != 1 {
		t.Errorf("gitlabOutcome() with metadata failure should register, got %d providers", len(out.providers))
	}
	if len(out.statuses) != 1 {
		t.Fatalf("gitlabOutcome() statuses = %d, want 1", len(out.statuses))
	}
	status := out.statuses[0]
	if !status.Available {
		t.Errorf("gitlabOutcome() available = false, want true")
	}
}
