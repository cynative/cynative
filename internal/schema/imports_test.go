package schema_test

import (
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPackageIsPureLeaf pins the pure-leaf contract from the package doc: every
// Go file under this directory imports only the standard library, the JSON
// Schema generator, or (external test files only) the package itself. The
// depguard "schema-pure-leaf" rule enforces the same contract at lint time, but
// it sees only the active build context and golangci-lint drops diagnostics
// from generated files, so this test parses every file regardless of build
// tags or generated markers.
func TestPackageIsPureLeaf(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil:
			return walkErr
		case entry.IsDir():
			return dirAction(path, entry.Name())
		case !strings.HasSuffix(entry.Name(), ".go"):
			return nil
		default:
			return checkFileImports(t, fset, path)
		}
	})
	if walkErr != nil {
		t.Fatalf("walking the package directory: %v", walkErr)
	}
}

// dirAction skips directories the go tool would not compile (none exist
// today) and descends into the rest.
func dirAction(path, name string) error {
	if path == "." {
		return nil
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" {
		return fs.SkipDir
	}
	return nil
}

// checkFileImports parses one Go file and reports every import outside the
// pure-leaf allowlist as a test failure.
func checkFileImports(t *testing.T, fset *token.FileSet, path string) error {
	t.Helper()

	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return err
	}
	for _, imp := range file.Imports {
		impPath, unquoteErr := strconv.Unquote(imp.Path.Value)
		if unquoteErr != nil {
			return unquoteErr
		}
		if !importAllowed(impPath, file.Name.Name, path) {
			t.Errorf("%s imports %q: internal/schema is a pure leaf (see the package doc)", path, impPath)
		}
	}
	return nil
}

// importAllowed reports whether the file at path, whose package clause is pkg,
// may import impPath. Beyond the two exact-match exceptions, an import is
// allowed only if it resolves into GOROOT, so a lookup failure is a violation,
// never a pass; that also rejects cgo's "C" pseudo-import, which no leaf
// serialization package has business using.
func importAllowed(impPath, pkg, path string) bool {
	if impPath == "github.com/invopop/jsonschema" {
		return true
	}
	if impPath == "github.com/cynative/cynative/internal/schema" {
		return pkg == "schema_test" && strings.HasSuffix(path, "_test.go")
	}
	resolved, err := build.Import(impPath, "", build.FindOnly)
	return err == nil && resolved.Goroot
}
