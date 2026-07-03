package auth

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"

	"github.com/cynative/cynative/internal/redact"
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
	out := &capWriter{max: glabStdoutCap}    //nolint:exhaustruct // buf grows.
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

// glabRedact redacts a string through the response redactor (secret-shaped content ->
// placeholders) before it can enter an error surfaced to logs or the model.
func glabRedact(s string) string { return redact.New().Redact(s) }

// discoverGitLabCred resolves the credential: an env token (exec-free static), else,
// when the glab path applies, the glab binary via credential-helper. Loud-vs-quiet is
// decided by decideGlab against an [os.Stat] config-presence signal.
func discoverGitLabCred(loginHost string, loginOK bool) (glabCredential, error) {
	if envTok := gitlabEnvToken(os.LookupEnv); envTok != "" {
		return glabCredential{AccessToken: envTok}, nil //nolint:exhaustruct // env PAT.
	}
	if !loginOK {
		return glabCredential{}, nil //nolint:exhaustruct // api_host-only: quiet.
	}
	configExists := glabConfigExists()
	glabPath, lookErr := lookGlab()
	if lookErr != nil {
		return decideGlab(loginHost, "", false, configExists, nil, nil, nil, glabRedact)
	}
	env := glabHelperEnv(os.Environ(), loginHost)
	stdout, stderr, execErr := runGlab(context.Background(), glabPath, glabHelperArgs(), env)
	return decideGlab(loginHost, glabPath, true, configExists, stdout, stderr, execErr, glabRedact)
}

// newTokenSource builds the credential source: a static source for an env/PAT token,
// else a caching glab-helper-backed source seeded with the discovered token.
func newTokenSource(_ *gitlabProvider, cred glabCredential) oauth2.TokenSource {
	if !cred.IsOAuth2 {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cred.AccessToken}) //nolint:exhaustruct // access.
	}
	return newGlabHelperSource(glabFetch(cred), time.Now, seedToken(cred))
}

// glabFetch returns the refresh closure: exec the pinned glab binary and parse the
// result into a token, validating the instance. glab performs its own OAuth-refresh
// network I/O here (to the configured instance, using the user's own glab config), so
// this refresh path is outside cynative's request-time transport guards (dial guard /
// CA / no-redirect / no-proxy) by design - it is a trusted, non-model-directed
// bootstrap operation, mirroring how the other connectors delegate to their vendor CLIs.
func glabFetch(cred glabCredential) func() (*oauth2.Token, error) {
	return func() (*oauth2.Token, error) {
		env := glabHelperEnv(os.Environ(), cred.Host)
		stdout, _, execErr := runGlab(context.Background(), cred.GlabPath, glabHelperArgs(), env)
		return tokenFromHelper(cred.Host, stdout, execErr, glabRedact)
	}
}
