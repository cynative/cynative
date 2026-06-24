package audit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// FileConfig configures the rotating audit file. It is owned by this package so
// it need not import internal/config; the composition root maps the config block
// onto it.
type FileConfig struct {
	Path          string
	MaxSizeMB     int
	RetentionDays int
	Compress      bool
}

// Open prepares the rotating audit writer. It creates the parent directory,
// probes writability (so a bad path fails the run at startup — lumberjack opens
// lazily on first write), forces the file mode to 0600 (it may hold sensitive
// arguments, and lumberjack would otherwise inherit a pre-existing wider mode),
// seeds the age anchor from the first record in the active file, and returns a
// size-rotating, age-retaining writer.
//
// Fail-closed scope: lumberjack's Write surfaces record-write and synchronous
// rotate (rename+reopen) errors, which propagate to the caller. Retention pruning
// and compression run asynchronously and their errors are discarded by lumberjack
// — they are intentionally not fail-closed.
func Open(cfg FileConfig) (io.WriteCloser, error) {
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir %q: %w", dir, err)
	}

	probe, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", cfg.Path, err)
	}
	if cerr := probe.Close(); cerr != nil {
		return nil, fmt.Errorf("audit: close probe %q: %w", cfg.Path, cerr)
	}
	if err = os.Chmod(cfg.Path, 0o600); err != nil {
		return nil, fmt.Errorf("audit: chmod %q: %w", cfg.Path, err)
	}

	oldest, _ := parseFirstRecordTime(readFirstLine(cfg.Path))
	lj := buildLumberjack(cfg)
	return newAgeRotatingWriter(lj, time.Now, retentionFromDays(cfg.RetentionDays), oldest), nil
}

// buildLumberjack constructs the underlying size-rotating lumberjack writer.
func buildLumberjack(cfg FileConfig) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSizeMB,
		MaxAge:     cfg.RetentionDays,
		MaxBackups: 0,
		LocalTime:  true,
		Compress:   cfg.Compress,
	}
}

// readFirstLine returns the first newline-terminated line of path, or nil when the
// file is absent or unreadable (best-effort seeding for age-based rotation).
func readFirstLine(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	line, _ := bufio.NewReader(f).ReadBytes('\n')
	return line
}
