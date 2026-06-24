package llm_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cynative/cynative/internal/llm"
)

// docsProvidersDir returns the absolute path to docs/providers from the
// location of this test file, regardless of where `go test` is invoked.
func docsProvidersDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/llm/providersdocs_test.go → repo root is three dirs up.
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "docs", "providers")
}

func TestEveryBifrostProviderHasADocFile(t *testing.T) {
	t.Parallel()

	dir := docsProvidersDir(t)

	for _, p := range llm.AllBifrostProviders {
		path := filepath.Join(dir, string(p)+".md")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("provider %q is in AllBifrostProviders but %s does not exist (err: %v)",
				p, filepath.Join("docs/providers", string(p)+".md"), err)
		}
	}
}

func TestProviderIndexExists(t *testing.T) {
	t.Parallel()

	dir := docsProvidersDir(t)
	path := filepath.Join(dir, "README.md")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("docs/providers/README.md does not exist (err: %v)", err)
	}
}
