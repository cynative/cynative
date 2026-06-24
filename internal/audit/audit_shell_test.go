package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/audit"
)

// wantPerm is the expected audit-file mode (named to satisfy the mnd linter on
// the mode comparisons below).
const wantPerm os.FileMode = 0o600

func TestOpen_CreatesFileWith0600(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sub", "audit.log")
	w, err := audit.Open(audit.FileConfig{Path: path, MaxSizeMB: 100, RetentionDays: 30, Compress: false})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != wantPerm {
		t.Errorf("perm: got %o want 600", perm)
	}
}

func TestOpen_ChmodsPreexisting0644(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w, err := audit.Open(audit.FileConfig{Path: path, MaxSizeMB: 100, RetentionDays: 30, Compress: false})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = w.Close() }()

	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != wantPerm {
		t.Errorf("perm after chmod: got %o want 600", perm)
	}
}

func TestOpen_BadPath_Errors(t *testing.T) {
	t.Parallel()

	// A path whose parent is a regular file cannot be created.
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := audit.Open(audit.FileConfig{Path: filepath.Join(file, "audit.log"), MaxSizeMB: 1, RetentionDays: 1})
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestOpen_WritesAppendableLine(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := audit.Open(audit.FileConfig{Path: path, MaxSizeMB: 100, RetentionDays: 30})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, werr := w.Write([]byte("line\n")); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	_ = w.Close()

	b, _ := os.ReadFile(path)
	if string(b) != "line\n" {
		t.Errorf("content: %q", b)
	}
}

func TestOpen_AgeRotatesStaleActiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Seed a stale active file: one record dated 3 days ago.
	stale := `{"time":"2026-06-19T00:00:00Z","seq":1,"actor":"seed","result":"seed"}` + "\n"
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := audit.Open(audit.FileConfig{Path: path, MaxSizeMB: 100, RetentionDays: 1, Compress: false})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = w.Close() }()

	if _, werr := w.Write([]byte(`{"time":"now","seq":2}` + "\n")); werr != nil {
		t.Fatalf("write: %v", werr)
	}

	// lumberjack rotates the stale active file to a timestamped backup.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var backups int
	for _, e := range entries {
		if e.Name() != "audit.log" && strings.HasPrefix(e.Name(), "audit-") {
			backups++
		}
	}
	if backups == 0 {
		t.Fatalf("expected a rotated backup for the stale active file; dir=%v", entries)
	}
}
