package auth

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeFakeGlab writes an executable shell script standing in for glab. Skips on
// Windows, where a #!/bin/sh shim does not execute (the gate runs tests on Linux).
func writeFakeGlab(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake glab is POSIX-only; the gate runs tests on Linux")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "glab")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func TestRunGlab_CapturesStdout(t *testing.T) {
	script := writeFakeGlab(t, "#!/bin/sh\nprintf '%s' '{\"type\":\"success\"}'\n")
	stdout, _, err := runGlab(context.Background(), script, glabHelperArgs(), []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatalf("runGlab err: %v", err)
	}
	if string(stdout) != `{"type":"success"}` {
		t.Fatalf("stdout = %q", string(stdout))
	}
}

func TestRunGlab_StdoutCapped(t *testing.T) {
	// Emit far more than the cap; runGlab must not hang and must truncate.
	script := writeFakeGlab(t, "#!/bin/sh\nyes X | head -c 200000\n")
	stdout, _, _ := runGlab(context.Background(), script, nil, []string{"PATH=/usr/bin"})
	if len(stdout) > glabStdoutCap {
		t.Fatalf("stdout len %d exceeds cap %d", len(stdout), glabStdoutCap)
	}
}

func TestRunGlab_NonZeroExitReturnsError(t *testing.T) {
	script := writeFakeGlab(t, "#!/bin/sh\nexit 1\n")
	_, _, err := runGlab(context.Background(), script, nil, []string{"PATH=/usr/bin"})
	if err == nil {
		t.Fatal("want error on non-zero exit")
	}
}

func TestLookGlab_AbsoluteOrError(t *testing.T) {
	t.Parallel()
	// On a host with glab, the path must be absolute; without it, an error. Either way
	// lookGlab never returns a relative path.
	path, err := lookGlab()
	if err == nil && !filepath.IsAbs(path) {
		t.Fatalf("lookGlab returned relative path %q", path)
	}
}

func TestGlabConfigExists_NoPanic(t *testing.T) {
	t.Parallel()
	// Smoke: reads the real env/home on the CI host; must return a bool without panic.
	_ = glabConfigExists()
}
