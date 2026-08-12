package agentcatalog_test

import (
	"testing"

	"github.com/cynative/cynative/internal/agentcatalog"
)

func TestCompose_WithUserInstruction(t *testing.T) {
	t.Parallel()

	def := agentcatalog.Definition{ //nolint:exhaustruct // only the composed fields matter.
		Description: "Finds public data stores.",
		Body:        "Check S3 and RDS.",
	}

	want := "agent description:\nFinds public data stores.\n\n" +
		"user instruction:\n12814983572854\n\n" +
		"agent instructions:\nCheck S3 and RDS."

	if got := agentcatalog.Compose(def, "12814983572854"); got != want {
		t.Fatalf("Compose() =\n%q\nwant\n%q", got, want)
	}
}

func TestCompose_WithoutUserInstruction(t *testing.T) {
	t.Parallel()

	def := agentcatalog.Definition{ //nolint:exhaustruct // only the composed fields matter.
		Description: "Finds public data stores.",
		Body:        "Check S3 and RDS.",
	}

	want := "agent description:\nFinds public data stores.\n\n" +
		"agent instructions:\nCheck S3 and RDS."

	if got := agentcatalog.Compose(def, ""); got != want {
		t.Fatalf("Compose() =\n%q\nwant\n%q", got, want)
	}
}

func TestCompose_PreservesBodyTrailingBytes(t *testing.T) {
	t.Parallel()

	def := agentcatalog.Definition{ //nolint:exhaustruct // only the composed fields matter.
		Description: "d",
		Body:        "line\n\n",
	}

	want := "agent description:\nd\n\nagent instructions:\nline\n\n"

	if got := agentcatalog.Compose(def, ""); got != want {
		t.Fatalf("Compose() = %q, want %q (no newline appended, body bytes kept)", got, want)
	}
}

// Compose emits fixed labels, so its output is non-empty for any Definition.
// The CLI's Welcome skip depends on that and on nothing else.
func TestCompose_NonEmptyForZeroDefinition(t *testing.T) {
	t.Parallel()

	zero := agentcatalog.Definition{} //nolint:exhaustruct // deliberate zero value.
	if got := agentcatalog.Compose(zero, ""); got == "" {
		t.Fatal("Compose() returned an empty string for the zero Definition")
	}
}
