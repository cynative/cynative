package cynative

import (
	"io/fs"
	"strings"
	"testing"
)

// TestBuiltinAgents_Embedded proves the built-in tier is really embedded. The
// directory ships empty (a .keep only), so this asserts the subtree exists and
// is walkable rather than asserting any agent is present.
func TestBuiltinAgents_Embedded(t *testing.T) {
	t.Parallel()

	sub, err := fs.Sub(BuiltinAgents(), "agents")
	if err != nil {
		t.Fatalf("fs.Sub(BuiltinAgents(), \"agents\") = %v, want nil", err)
	}

	if _, rerr := fs.ReadDir(sub, "."); rerr != nil {
		t.Fatalf("ReadDir on the embedded agents dir = %v, want nil", rerr)
	}
}

// TestBuiltinAgents_EveryFileIsValid is the derived-catalog guard. It passes
// vacuously while the tier is empty and starts biting the moment a built-in
// lands, matching the connector and provider doc-table convention.
//
// It checks only the fence prefix, because the module-root package does not
// depend on the catalog. Full validation (ValidName on the stem, Parse on the
// contents) lives in internal/cli, which imports both.
func TestBuiltinAgents_EveryFileIsValid(t *testing.T) {
	t.Parallel()

	sub, err := fs.Sub(BuiltinAgents(), "agents")
	if err != nil {
		t.Fatalf("fs.Sub() = %v", err)
	}

	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		t.Fatalf("ReadDir() = %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}

		data, rerr := fs.ReadFile(sub, e.Name())
		if rerr != nil {
			t.Errorf("ReadFile(%s) = %v", e.Name(), rerr)

			continue
		}
		if !strings.HasPrefix(string(data), "---\n") && !strings.HasPrefix(string(data), "---\r\n") {
			t.Errorf("built-in agent %s does not begin with a frontmatter fence", e.Name())
		}
	}
}
