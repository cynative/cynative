package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// TestBoundToolSchemas_ContainNoSecretShapedContent extends the §5.4 invariant to
// the orchestration tools the agent binds for the model (write_todos, task, and
// verify_findings — verification is unconditional). New builds them internally, so
// the test scans every entry in a.tools.infos — the exact set offered to Generate
// as its tools arg.
func TestBoundToolSchemas_ContainNoSecretShapedContent(t *testing.T) {
	t.Parallel()

	// A zero Config suffices: verify_findings is always bound and New reads only Cfg
	// here, so the other Config fields can stay zero.
	a, err := New(context.Background(), Config{}) //nolint:exhaustruct // only Cfg matters; defaults zero.
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r := redact.New()
	for _, info := range a.tools.infos {
		rendered := info.Desc
		if info.Params != nil {
			b, marshalErr := json.Marshal(info.Params)
			if marshalErr != nil {
				t.Fatalf("marshal params for %s: %v", info.Name, marshalErr)
			}
			rendered += string(b)
		}
		if got := r.Redact(rendered); got != rendered {
			t.Errorf("bound tool %q schema contains secret-shaped content:\nbefore: %s\nafter:  %s",
				info.Name, rendered, got)
		}
	}

	// Sanity: the orchestration tools are actually present, so the scan is meaningful.
	for _, name := range []string{"write_todos", "task", "verify_findings"} {
		if _, ok := a.tools.tools[name]; !ok {
			t.Fatalf("orchestration tool %q not bound", name)
		}
	}
}
