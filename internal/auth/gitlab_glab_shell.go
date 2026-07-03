package auth

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// glab exec bounds. The timeout covers a network refresh; WaitDelay bounds the
// post-kill drain. Output caps bound memory from a misbehaving child.
const (
	glabExecTimeout = 30 * time.Second
	glabWaitDelay   = 5 * time.Second
	glabStdoutCap   = 64 << 10
	glabStderrCap   = 8 << 10
)

// lookGlab resolves the glab binary to an absolute path once, failing closed on a
// relative result (exec.ErrDot) so a poisoned working directory cannot supply glab.
func lookGlab() (string, error) {
	path, err := exec.LookPath("glab")
	if err != nil {
		return "", fmt.Errorf("gitlab: glab not found: %w", err)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("gitlab: refusing non-absolute glab path %q", path)
	}
	return path, nil
}

// runGlab executes the pinned glab binary with a fixed argv and curated env in a
// neutral working directory, with a nil stdin (Go connects the null device), a
// timeout, and a WaitDelay. Output is captured through bounded cap writers that drain
// to EOF so the child's pipe closes and Wait returns. Returns captured stdout, stderr,
// and any run error.
func runGlab(ctx context.Context, glabPath string, args, env []string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, glabExecTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, glabPath, args...)
	cmd.Env = env
	cmd.Dir = os.TempDir()
	cmd.WaitDelay = glabWaitDelay
	out := &capWriter{max: glabStdoutCap}   //nolint:exhaustruct // buf grows.
	errOut := &capWriter{max: glabStderrCap} //nolint:exhaustruct // buf grows.
	cmd.Stdout = out
	cmd.Stderr = errOut

	err := cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// glabConfigExists reports whether any candidate glab config.yml is present. It stats
// (never parses) so a keyring-only user (whose config.yml has host metadata but no
// token) still counts, and no credential contents are read.
func glabConfigExists() bool {
	glabDir, _ := os.LookupEnv("GLAB_CONFIG_DIR")
	xdg, _ := os.LookupEnv("XDG_CONFIG_HOME")
	userCfg, _ := os.UserConfigDir()
	for _, p := range glabConfigPaths(glabDir, xdg, userCfg, homeDirOrEmpty()) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
