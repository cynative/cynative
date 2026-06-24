package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

// glabDefaultConfigMode is the permission bits glab uses when creating config.yml.
const glabDefaultConfigMode os.FileMode = 0o600

// refreshViaOAuth2 performs the OAuth refresh through golang.org/x/oauth2 (the
// same library glab uses), capturing the rotated refresh token. Bootstrap-call
// invariants (spec §4.4): the TokenURL host/port is connector-derived
// (p.servedHost); the pinned client (refreshClient → buildProbeClient) enforces
// dial-guard + CA + no-redirect + no-proxy + a concrete timeout; AuthStyleInParams
// puts the public client_id in the body, never HTTP Basic. The ctx is
// background-scoped (the source outlives any single request); the bound is the
// client timeout.
func refreshViaOAuth2(p *gitlabProvider, clientID string, tok *oauth2.Token) (*oauth2.Token, error) {
	hc, err := refreshClient(p)
	if err != nil {
		return nil, err
	}

	cfg := &oauth2.Config{ //nolint:exhaustruct // only ClientID + Endpoint are used for refresh.
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			TokenURL:  "https://" + p.servedHost() + "/oauth/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	// Seed with an explicitly-invalid token (empty AccessToken → oauth2.Token.Valid()
	// is false) carrying only the refresh token, so cfg.TokenSource ALWAYS performs
	// the refresh_token POST and never no-ops on a token x/oauth2 deems still valid
	// (it treats a zero Expiry as valid). The source only calls this once it has
	// already decided the token is expired, so forcing the POST is correct.
	seed := &oauth2.Token{RefreshToken: tok.RefreshToken} //nolint:exhaustruct // refresh only.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, hc)
	newTok, err := cfg.TokenSource(ctx, seed).Token()
	if err != nil {
		return nil, fmt.Errorf("gitlab: oauth refresh: %w", err)
	}

	return newTok, nil
}

// writeBackGlabConfig persists newTok's three OAuth fields under hosts[host] in
// the glab config at path, adopt-and-skip aware. It resolves symlinks (writes the
// real target, preserving the link), then either adopts a concurrent same-host
// rotation — detected by the host's on-disk refresh token differing from
// diskSnapshotRefresh (the pre-refresh disk snapshot) — (returns the on-disk
// token, skips the write) or rebases the three fields onto the latest tree and
// writes atomically (mode-preserving temp+rename + parent-dir fsync). Returns the
// token to use. See spec §4.5.
func writeBackGlabConfig(path, host, diskSnapshotRefresh string, newTok *oauth2.Token) (*oauth2.Token, error) {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("gitlab: resolve config path %q: %w", path, err) // pre-proof → fail closed.
	}

	out, adopted, prepErr := prepareGlabWriteBack(realPath, host, diskSnapshotRefresh, newTok)
	if prepErr != nil {
		return nil, prepErr // read/parse error or errGitLabHostNotOAuth → pre-proof → fail closed.
	}
	if adopted != nil {
		return adopted, nil // concurrent rotation: adopt, do not clobber.
	}
	// Reaching here means prepareGlabWriteBack proved the on-disk host is still our
	// OAuth credential. A failure now is a POST-proof persistence failure: the rotation
	// is irreversible, so mark it so the caller may use the minted token and warn.
	if writeErr := atomicWriteFile(realPath, out); writeErr != nil {
		return nil, fmt.Errorf("%w: %w", errGitLabPersistFailed, writeErr)
	}

	return newTok, nil
}

// prepareGlabWriteBack re-reads the real config and returns either the bytes to
// write (rebased onto the latest tree) or the adopted on-disk token when a
// concurrent writer changed the host's refresh token since diskSnapshotRefresh. It
// refuses (errGitLabHostNotOAuth) when the host is present but non-OAuth — the user
// switched to a PAT during the refresh window, and local config is the source of
// truth. Exactly one of (out, adopted) is set.
func prepareGlabWriteBack(
	realPath, host, diskSnapshotRefresh string,
	newTok *oauth2.Token,
) ([]byte, *oauth2.Token, error) {
	cur, latest, err := readAndParseHost(realPath, host)
	if err != nil {
		return nil, nil, err
	}
	// Refresh-back is allowed ONLY onto a present OAuth credential for the host. A
	// host whose token was removed/blanked, or replaced by a non-OAuth (PAT) token,
	// during the refresh window must NOT be clobbered — local config is the source
	// of truth, so fail closed.
	if cur.AccessToken == "" || !cur.IsOAuth2 {
		return nil, nil, errGitLabHostNotOAuth
	}
	if adopted, ok := adoptOnDiskRotation(cur, diskSnapshotRefresh); ok {
		return nil, adopted, nil
	}
	out, rebaseErr := rebaseGlabConfig(latest, host, newTok)
	if rebaseErr != nil {
		return nil, nil, rebaseErr
	}

	return out, nil, nil
}

// readAndParseHost re-reads the real config file and parses the credential for
// host. It returns the parsed credential plus the raw bytes (which the caller
// rebases the new token onto, preserving unrelated concurrent edits).
func readAndParseHost(realPath, host string) (glabCredential, []byte, error) {
	latest, err := os.ReadFile(realPath)
	if err != nil {
		//nolint:exhaustruct // err return.
		return glabCredential{}, nil, fmt.Errorf("gitlab: re-read config %q: %w", realPath, err)
	}
	cur, err := parseGlabCred(latest, host)
	if err != nil {
		return glabCredential{}, nil, err //nolint:exhaustruct // err.
	}

	return cur, latest, nil
}

// atomicWriteFile writes data to a temp file in path's directory (preserving
// path's existing mode), fsyncs it, renames it over path, and fsyncs the parent
// directory so the rename is durable.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, createErr := os.CreateTemp(dir, ".glab-config-*.tmp")
	if createErr != nil {
		return fmt.Errorf("gitlab: create temp config: %w", createErr)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename; best-effort cleanup.

	if syncErr := writeSyncClose(tmp, data, existingMode(path)); syncErr != nil {
		return syncErr
	}
	if renameErr := os.Rename(tmpName, path); renameErr != nil {
		return fmt.Errorf("gitlab: rename config: %w", renameErr)
	}

	return fsyncDir(dir)
}

// existingMode returns path's current permission bits, or glabDefaultConfigMode
// when it cannot be stat'd.
func existingMode(path string) os.FileMode {
	if fi, statErr := os.Stat(path); statErr == nil {
		return fi.Mode().Perm()
	}

	return glabDefaultConfigMode
}

// writeSyncClose writes data to f, chmods it, fsyncs, and closes it.
func writeSyncClose(f *os.File, data []byte, mode os.FileMode) error {
	if _, writeErr := f.Write(data); writeErr != nil {
		_ = f.Close()

		return fmt.Errorf("gitlab: write temp config: %w", writeErr)
	}
	if chmodErr := f.Chmod(mode); chmodErr != nil {
		_ = f.Close()

		return fmt.Errorf("gitlab: chmod temp config: %w", chmodErr)
	}
	if syncErr := f.Sync(); syncErr != nil {
		_ = f.Close()

		return fmt.Errorf("gitlab: fsync temp config: %w", syncErr)
	}

	return f.Close()
}

// fsyncDir fsyncs a directory so a contained rename is durable. Windows has no
// directory fsync (rename durability is best-effort there), so it is skipped; on
// every other platform a genuine open/sync failure is propagated so a durability
// failure after the irreversible refresh is never reported as a successful write.
func fsyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil // directory fsync is unsupported on Windows; rename durability is best-effort there.
	}
	d, openErr := os.Open(dir)
	if openErr != nil {
		return fmt.Errorf("gitlab: open config dir for fsync: %w", openErr)
	}
	defer d.Close()
	if syncErr := d.Sync(); syncErr != nil {
		return fmt.Errorf("gitlab: fsync config dir: %w", syncErr)
	}

	return nil
}

// probeConfigRefreshable proves, BEFORE the irreversible refresh, that the exact
// glab config file can be both READ (EvalSymlinks + ReadFile, so write-back's
// re-read/rebase will succeed) and atomically WRITTEN (dirWriteProbe). Fail-closed:
// any failure means the rotated token could not be persisted, so the caller must
// not burn the single-use refresh token.
func probeConfigRefreshable(path string) error {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("gitlab: resolve config path %q: %w", path, err)
	}
	if _, readErr := os.ReadFile(realPath); readErr != nil {
		return fmt.Errorf("gitlab: read config %q: %w", realPath, readErr)
	}

	return dirWriteProbe(realPath)
}

// dirWriteProbe proves the atomic write path works BEFORE the irreversible refresh
// (spec §4.6): it creates, fsyncs, renames, and unlinks a probe temp file in the
// config's real directory, without touching the real config. A failure means
// write-back would fail, so the caller must not burn the single-use refresh token.
func dirWriteProbe(path string) error {
	probePath := path
	if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
		probePath = resolved
	}
	dir := filepath.Dir(probePath)

	probe, createErr := os.CreateTemp(dir, ".glab-probe-*.tmp")
	if createErr != nil {
		return fmt.Errorf("gitlab: config dir not writable: %w", createErr)
	}
	name := probe.Name()
	if syncErr := writeSyncClose(probe, []byte("probe"), glabDefaultConfigMode); syncErr != nil {
		_ = os.Remove(name)

		return syncErr
	}
	renamed := name + ".renamed"
	if renameErr := os.Rename(name, renamed); renameErr != nil {
		_ = os.Remove(name)

		return fmt.Errorf("gitlab: config dir rename probe failed: %w", renameErr)
	}
	_ = os.Remove(renamed)

	return fsyncDir(dir)
}

// discoverGitLabCredFrom is the pure-seam core of discovery (env lookup + per-host
// config parse). Exposed for the shell entry; logic is gitlabCredFromConfig.
// configPath is the exact file configYAML was read from, threaded onto the
// credential so the source's re-reads/probe/write-back target it.
func discoverGitLabCredFrom(
	lookup func(string) (string, bool),
	configPath string,
	configYAML []byte,
	hosts []string,
) (glabCredential, error) {
	return gitlabCredFromConfig(gitlabEnvToken(lookup), configPath, configYAML, hosts)
}

// discoverGitLabCred resolves the full glab credential for the candidate hosts:
// GITLAB_TOKEN env first, then the glab config.yml. Shell I/O.
func discoverGitLabCred(hosts []string) (glabCredential, error) {
	path, data := readGlabConfigWithPath()

	return discoverGitLabCredFrom(os.LookupEnv, path, data, hosts)
}

// newTokenSource builds the credential source: a static source for a non-OAuth
// token (PAT/env), else a refreshing glabOAuthSource for a glab OAuth token. The
// OAuth source is built even when refresh is impossible (unresolved client_id or
// unwritable config): its Token() returns the token while valid and the precise
// errGitLabRefreshDead once expired — never a lossy access-only static token.
func newTokenSource(p *gitlabProvider, cred glabCredential) oauth2.TokenSource {
	if !cred.IsOAuth2 {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cred.AccessToken}) //nolint:exhaustruct // access.
	}

	clientID, _ := resolveOAuthClientID(p.servedHost(), cred) // "" → source returns dead once expired.

	return newGlabOAuthSource(p, cred, clientID)
}

// newGlabOAuthSource wires the refreshing source's production seams. It reads,
// probes, and writes back cred.ConfigPath — the exact file the credential was read
// from — so the read source and the rotation target never diverge. A "" ConfigPath
// makes the probe fail (refresh impossible) without touching the filesystem.
func newGlabOAuthSource(p *gitlabProvider, cred glabCredential, clientID string) *glabOAuthSource {
	return &glabOAuthSource{ //nolint:exhaustruct // mu zero-valued.
		host:     cred.Host,
		clientID: clientID,
		cached:   credToToken(cred),
		readCreds: func() (glabCredential, error) {
			data, err := os.ReadFile(cred.ConfigPath)
			if err != nil {
				//nolint:exhaustruct // err return.
				return glabCredential{}, fmt.Errorf("gitlab: read glab config %q: %w", cred.ConfigPath, err)
			}

			return parseGlabCred(data, cred.Host)
		},
		probe: func() error {
			if cred.ConfigPath == "" {
				return errGitLabRefreshDead
			}

			return probeConfigRefreshable(cred.ConfigPath)
		},
		refresh: func(tok *oauth2.Token) (*oauth2.Token, error) { return refreshViaOAuth2(p, clientID, tok) },
		writeBack: func(diskSnapshotRefresh string, newTok *oauth2.Token) (*oauth2.Token, error) {
			return writeBackGlabConfig(cred.ConfigPath, cred.Host, diskSnapshotRefresh, newTok)
		},
		warn: func(err error) {
			fmt.Fprintf(os.Stderr, "⚠️ gitlab: refreshed OAuth token but could not update glab config: %v "+
				"(run `glab auth login` to re-establish glab's session)\n", err)
		},
		now:   time.Now,
		sleep: time.Sleep,
	}
}
