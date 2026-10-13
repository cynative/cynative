package gitlab_test

import (
	"slices"
	"testing"

	"github.com/cynative/cynative/internal/auth/gitlab"
)

// TestDistillReleaseDocs_RecordsNoAdmissionGap pins that a release document's docs carry no gate verdict: the gate
// classifies against master, so a check against a table built from the release's own bytes would answer for the
// wrong document. DistillDocs, which serves master, still records it.
func TestDistillReleaseDocs_RecordsNoAdmissionGap(t *testing.T) {
	t.Parallel()
	release, err := gitlab.DistillReleaseDocs([]byte(docsFixture))
	if err != nil {
		t.Fatal(err)
	}
	master := docsFixtureDocs(t)
	if len(release.Ops) != len(master.Ops) || release.SHA256 != master.SHA256 || release.Version != master.Version {
		t.Fatalf("release ops %d sha %q version %q, master ops %d sha %q version %q", len(release.Ops),
			release.SHA256, release.Version, len(master.Ops), master.SHA256, master.Version)
	}
	const id = "getApiV4SwaggerDoc"
	if gaps := master.Ops[id].Gaps; !slices.Equal(gaps, []string{"rendered path is not admitted by the gitlab gate"}) {
		t.Errorf("master gaps = %q", gaps)
	}
	for name, op := range release.Ops {
		if len(op.Gaps) != 0 {
			t.Errorf("%s: release gaps = %q", name, op.Gaps)
		}
	}
	if release.Ops[id].Path != master.Ops[id].Path {
		t.Errorf("release path %q, master path %q", release.Ops[id].Path, master.Ops[id].Path)
	}
}

func TestDistillReleaseDocs_Rejects(t *testing.T) {
	t.Parallel()
	if d, err := gitlab.DistillReleaseDocs([]byte("paths: [a")); err == nil || d != nil {
		t.Errorf("docs %+v err %v", d, err)
	}
}
