package agent

import (
	"context"
	"io"
	"testing"

	"github.com/cynative/cynative/internal/config"
	"github.com/cynative/cynative/internal/schema"
)

func TestNew_MintsSessionIDViaInjectedGenerator(t *testing.T) {
	t.Parallel()

	a := New(context.Background(), config0Cfg(), WithNewID(seqIDs("S1", "ignored")))
	if a.sessionID != "S1" {
		t.Errorf("sessionID: got %q want S1", a.sessionID)
	}
}

// config0Cfg is a minimal valid agent Config for construction tests.
func config0Cfg() Config {
	return Config{ //nolint:exhaustruct // construction-only fields.
		Model: nil,
		Cfg: config.Config{ //nolint:exhaustruct // construction-only fields.
			RenderStyle:           "notty",
			MaxIterations:         1,
			MaxSubagentIterations: 1,
		},
		Renderer: func(*schema.Message, string, io.Writer) {},
	}
}

// seqIDs returns a generator that yields the given ids in order, then "".
func seqIDs(ids ...string) func() string {
	i := 0

	return func() string {
		if i >= len(ids) {
			return ""
		}
		id := ids[i]
		i++

		return id
	}
}
