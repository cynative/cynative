package auth

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

// gitlabDefaultClientID is glab's hardcoded public OAuth client_id for gitlab.com
// (glab's internal/glinstance.DefaultClientID). It is a PKCE public client with no
// secret, so embedding it is safe. Self-managed instances supply their own
// client_id via glab's per-host config "client_id" key.
const gitlabDefaultClientID = "41d48f9422ebd655dd9cf2947d6979681dfaddc6d0c56f7628f6ada59559af1e"

// Token-lifecycle tuning. tokenRefreshSkew refreshes slightly before the hard
// expiry so an in-flight request never carries an about-to-expire token.
const (
	tokenRefreshSkew     = 60 * time.Second
	refreshTimeout       = 30 * time.Second
	invalidGrantDeadline = 1 * time.Second
	invalidGrantBackoff  = 100 * time.Millisecond
)

// errGitLabRefreshDead is the terminal "the OAuth session is genuinely dead"
// error: the refresh token no longer works (or refresh is impossible) and no
// concurrent process produced a fresh one within the recovery deadline. Its
// message is the operator steer.
var errGitLabRefreshDead = errors.New(
	"gitlab OAuth session expired — run `glab auth login`, or set GITLAB_TOKEN to a PAT for unattended use")

// errGitLabHostNotOAuth means the glab config host is no longer an OAuth
// credential (the user switched to a PAT or removed it). The local config is the
// source of truth, so cynative refuses to refresh or overwrite it.
var errGitLabHostNotOAuth = errors.New("gitlab: glab config host is no longer an OAuth credential")

// errGitLabPersistFailed marks a write-back failure that occurred AFTER confirming
// the on-disk host is still our OAuth credential (the atomic write/rename/fsync
// failed). The rotation is irreversible, so the caller may use the minted token
// for this session and warn. Pre-proof failures (config removed/unreadable/changed)
// do NOT use this sentinel and must fail closed.
var errGitLabPersistFailed = errors.New("gitlab: refreshed token could not be persisted to glab config")

// glabCredential is the full credential discovered from glab config or the
// environment. Host is the matched hosts[] key (where write-back targets);
// it is "" for an environment token (which never writes back). AccessToken == ""
// means no credential was found. IsOAuth2 marks a refreshable glab OAuth token.
type glabCredential struct {
	Host         string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	IsOAuth2     bool
	ClientID     string // self-managed per-host client_id; "" for gitlab.com (uses the default).
	// ConfigPath is the glab config file the credential was read from ("" for env
	// tokens). All per-resolution re-reads, the directory write-probe, and the
	// write-back target THIS exact path, so they cannot diverge from the read source.
	ConfigPath string
}

// tokenExpired reports whether tok needs a refresh as of now. It is used ONLY by
// the refreshable glab OAuth source (static PAT/env tokens use StaticTokenSource
// and never reach this), so a zero/unknown Expiry counts as **expired**: an OAuth
// token always has a real expiry in practice, and a missing/unparseable one means
// we must refresh to obtain a known-good token rather than keep injecting a token
// that may already be dead server-side. Otherwise it is expired once now is within
// tokenRefreshSkew of the hard expiry.
func tokenExpired(tok *oauth2.Token, now time.Time) bool {
	if tok.Expiry.IsZero() {
		return true
	}

	return now.Add(tokenRefreshSkew).After(tok.Expiry)
}

// freshestToken returns whichever of a, b carries the later Expiry (the fresher
// token). nil args are ignored; a tie prefers b (the on-disk read, which reflects
// an external writer). Both nil returns nil.
func freshestToken(a, b *oauth2.Token) *oauth2.Token {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case a.Expiry.After(b.Expiry):
		return a
	default:
		return b
	}
}

// credToToken converts a discovered credential to an oauth2.Token (access/refresh/
// expiry only), or nil when no access token is present.
func credToToken(c glabCredential) *oauth2.Token {
	if c.AccessToken == "" {
		return nil
	}

	return &oauth2.Token{ //nolint:exhaustruct // only these fields are meaningful.
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		Expiry:       c.Expiry,
	}
}

// parseGlabCred extracts the full OAuth credential for host from raw glab
// config bytes. It tolerates glab's "!!null"-tagged scalars (captured as
// yaml.Node). Returns a zero credential (AccessToken == "")
// when the host or its token is absent. oauth2_expiry_date is parsed RFC3339
// first, then RFC822/RFC822Z (glab's read fallback for old configs); an
// unparseable date is left zero (treated as "expired" downstream, forcing a
// refresh) rather than failing the whole parse.
func parseGlabCred(configYAML []byte, host string) (glabCredential, error) {
	if len(configYAML) == 0 {
		return glabCredential{}, nil //nolint:exhaustruct // absent.
	}

	var cfg struct {
		Hosts map[string]struct {
			Token        yaml.Node `yaml:"token"`
			RefreshToken yaml.Node `yaml:"oauth2_refresh_token"`
			ExpiryDate   yaml.Node `yaml:"oauth2_expiry_date"`
			// IsOAuth2 is captured as a yaml.Node to tolerate glab's on-disk serialization,
			// which writes is_oauth2 as a quoted string ("true") rather than a bare boolean.
			// yaml.v3 cannot unmarshal a !!str "true" into a Go bool, so we read it as a
			// Node and derive the bool via strings.EqualFold below.
			IsOAuth2 yaml.Node `yaml:"is_oauth2"`
			ClientID yaml.Node `yaml:"client_id"`
		} `yaml:"hosts"`
	}
	if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
		return glabCredential{}, fmt.Errorf("gitlab: parse glab config: %w", err) //nolint:exhaustruct // err.
	}

	h, ok := cfg.Hosts[host]
	if !ok || h.Token.Value == "" {
		return glabCredential{}, nil //nolint:exhaustruct // absent.
	}

	return glabCredential{
		Host:         host,
		AccessToken:  h.Token.Value,
		RefreshToken: h.RefreshToken.Value,
		Expiry:       parseGlabExpiry(h.ExpiryDate.Value),
		IsOAuth2:     strings.EqualFold(h.IsOAuth2.Value, "true"),
		ClientID:     h.ClientID.Value,
	}, nil
}

// firstReadableConfig returns the (path, bytes) of the first path that read
// succeeds on, or ("", nil) when none is readable. Pure: read is injected so the
// identity (which path the bytes came from) is established in one place and reused
// by the probe + write-back, rather than re-derived independently.
func firstReadableConfig(paths []string, read func(string) ([]byte, error)) (string, []byte) {
	for _, path := range paths {
		if b, err := read(path); err == nil {
			return path, b
		}
	}

	return "", nil
}

// gitlabCredFromConfig returns the first credential found across hosts: the env
// token (a non-OAuth PAT, Host "" and ConfigPath "") when set, else the glab
// config credential for the first host that has a token, stamped with configPath
// (the file configYAML was read from) so re-reads, the write-probe, and write-back
// all target that exact path. A malformed config surfaces as an error.
func gitlabCredFromConfig(
	envToken, configPath string,
	configYAML []byte,
	hosts []string,
) (glabCredential, error) {
	if envToken != "" {
		return glabCredential{AccessToken: envToken}, nil //nolint:exhaustruct // env PAT, no host/oauth/path.
	}
	for _, h := range hosts {
		cred, err := parseGlabCred(configYAML, h)
		if err != nil {
			return glabCredential{}, err //nolint:exhaustruct // err.
		}
		if cred.AccessToken != "" {
			cred.ConfigPath = configPath

			return cred, nil
		}
	}

	return glabCredential{}, nil //nolint:exhaustruct // absent.
}

// parseGlabExpiry parses glab's oauth2_expiry_date. glab writes RFC3339 (which
// carries an unambiguous Z or numeric offset), so only RFC3339 is accepted. An
// empty, legacy, or otherwise unparseable value — including an RFC822-style zone
// ABBREVIATION (e.g. "18 Aug 25 19:18 JST") — yields the zero time rather than a
// fabricated offset: [time.Parse] invents a zero-offset zone for unknown
// abbreviations, which could make an already-expired token look valid for hours.
// A zero expiry is treated as expired by tokenExpired, so the OAuth source simply
// refreshes and rewrites the date as RFC3339 — fail-safe, never fail-stale.
func parseGlabExpiry(v string) time.Time {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}

	return time.Time{}
}

// resolveOAuthClientID returns the OAuth client_id to use for refresh and whether
// one is available. gitlab.com (the default public host, port-insensitive) uses
// the baked-in public client_id; any other (self-managed) host uses the per-host
// client_id glab stored, and is unresolved (ok=false) when that is absent —
// glab has no default or dynamic registration for self-managed instances.
func resolveOAuthClientID(servedHost string, cred glabCredential) (string, bool) {
	if stripHostPort(servedHost) == defaultGitLabHost {
		return gitlabDefaultClientID, true
	}
	if cred.ClientID != "" {
		return cred.ClientID, true
	}

	return "", false
}

// glab config key names this connector reads/writes.
const (
	glabKeyToken   = "token"
	glabKeyRefresh = "oauth2_refresh_token"
	glabKeyExpiry  = "oauth2_expiry_date"
	glabKeyHosts   = "hosts"
)

// errGitLabHostNodeMissing means the host the credential was discovered under is
// no longer present in the (re-read) config tree — refuse to write rather than
// inventing a section.
var errGitLabHostNodeMissing = errors.New("gitlab: host node absent in glab config on rebase")

// rebaseGlabConfig returns latestYAML with only token/oauth2_refresh_token/
// oauth2_expiry_date under hosts[host] replaced by newTok, preserving every other
// key, comment, and host (yaml.Node round-trip). The caller passes the FRESHEST
// on-disk bytes (re-read immediately before commit), so an unrelated concurrent
// edit present at that read survives. Expiry is written RFC3339 (glab's format).
// rebaseGlabConfig wraps rebaseGlabConfigWith with the real yaml.Marshal.
func rebaseGlabConfig(latestYAML []byte, host string, newTok *oauth2.Token) ([]byte, error) {
	return rebaseGlabConfigWith(latestYAML, host, newTok, yaml.Marshal)
}

// rebaseGlabConfigWith is the injectable core of rebaseGlabConfig; marshalFn is
// injected in tests to exercise the marshal-error path.
func rebaseGlabConfigWith(
	latestYAML []byte,
	host string,
	newTok *oauth2.Token,
	marshalFn func(any) ([]byte, error),
) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(latestYAML, &doc); err != nil {
		return nil, fmt.Errorf("gitlab: parse glab config on rebase: %w", err)
	}

	hostNode := mappingValue(mappingValue(documentRoot(&doc), glabKeyHosts), host)
	if hostNode == nil || hostNode.Kind != yaml.MappingNode {
		return nil, errGitLabHostNodeMissing
	}

	setMappingScalar(hostNode, glabKeyToken, newTok.AccessToken)
	if newTok.RefreshToken != "" {
		setMappingScalar(hostNode, glabKeyRefresh, newTok.RefreshToken)
	}
	if !newTok.Expiry.IsZero() {
		setMappingScalar(hostNode, glabKeyExpiry, newTok.Expiry.UTC().Format(time.RFC3339))
	}

	out, err := marshalFn(&doc)
	if err != nil {
		return nil, fmt.Errorf("gitlab: marshal glab config on rebase: %w", err)
	}

	return out, nil
}

// documentRoot returns the mapping node at the root of a parsed document (the
// single child of a DocumentNode), or the node itself when already a mapping.
func documentRoot(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0]
	}

	return n
}

// mappingValue returns the value node for key in a mapping node, or nil. yaml.v3
// mapping Content is [key0, val0, key1, val1, ...].
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}

	return nil
}

// setMappingScalar sets key's scalar value in mapping m, updating in place when
// present (preserving comments/style) or appending a new scalar pair otherwise.
func setMappingScalar(m *yaml.Node, key, value string) {
	if v := mappingValue(m, key); v != nil {
		v.SetString(value)

		return
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key} //nolint:exhaustruct // scalar.
	valNode := &yaml.Node{}                                  //nolint:exhaustruct // set below.
	valNode.SetString(value)
	m.Content = append(m.Content, keyNode, valNode)
}

// glabOAuthSource is the refreshing oauth2.TokenSource for a glab OAuth token.
// Each Token() re-reads the on-disk credential and uses the freshest of
// {in-memory, on-disk}; it refreshes (and writes the rotation back) only when
// that freshest token is expired. Refresh is gated by a per-call write-probe so
// the single-use refresh token is never burned when the rotation cannot be
// persisted. When refresh is impossible the source still returns a valid token
// and only fails with errGitLabRefreshDead once the token is expired. All I/O is
// injected (see the naming contract); production wiring lives in
// gitlab_oauth_shell.go. Token() is mutex-serialized and safe for concurrent use.
type glabOAuthSource struct {
	host     string // matched glab hosts[] key (read/write target).
	clientID string // "" → refresh impossible (self-managed without a client_id).

	mu     sync.Mutex
	cached *oauth2.Token

	readCreds func() (glabCredential, error)
	probe     func() error
	refresh   func(*oauth2.Token) (*oauth2.Token, error)
	writeBack func(diskSnapshotRefresh string, newTok *oauth2.Token) (*oauth2.Token, error)
	warn      func(error)
	now       func() time.Time
	sleep     func(time.Duration)
}

var _ oauth2.TokenSource = (*glabOAuthSource)(nil)

// Token returns the current access token, refreshing and persisting on rotation.
func (s *glabOAuthSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, disk, err := s.freshest()
	if err != nil {
		return nil, err
	}
	if !tokenExpired(current, s.now()) {
		s.cached = current

		return current, nil
	}

	// Refresh only when the on-disk host is still a refreshable OAuth credential.
	// Local config is the source of truth: a removed host or a PAT/non-OAuth
	// replacement (a deliberate logout/switch) must not be refreshed or clobbered.
	if s.clientID == "" || !disk.IsOAuth2 || disk.RefreshToken == "" {
		return nil, errGitLabRefreshDead
	}
	if probeErr := s.probe(); probeErr != nil {
		return nil, errGitLabRefreshDead
	}

	newTok, err := s.refresh(current)
	if err != nil {
		return s.recover(err)
	}

	// Pass the pre-refresh DISK snapshot (disk.RefreshToken) to write-back, not
	// current's refresh token: after an earlier write-back failure, current may be a
	// cached, never-persisted token while disk still holds the old token — comparing
	// against current would misread the stale disk token as a concurrent winner and
	// adopt it.
	used, wbErr := s.writeBack(disk.RefreshToken, newTok)
	if wbErr != nil {
		if errors.Is(wbErr, errGitLabPersistFailed) {
			// Proved the on-disk host is still our OAuth credential, but the atomic write
			// failed. The rotation is irreversible; use the minted token for this session
			// and warn loudly that glab's config was not updated.
			s.warn(wbErr)
			s.cached = newTok

			return newTok, nil
		}
		// Could not confirm the on-disk host is still our OAuth credential (config
		// removed/unreadable/changed during the refresh window): respect local config as
		// the source of truth and fail closed — do not attach the freshly-minted token.
		return nil, errGitLabRefreshDead
	}
	s.cached = used

	return used, nil
}

// freshest re-reads the on-disk credential and returns whichever of {cached,
// on-disk} is fresher (later expiry), plus the freshly-read on-disk credential
// (the pre-refresh snapshot for adopt-and-skip and the source-of-truth gate). On a
// read FAILURE it keeps using the cached token only while that token is still valid
// (a transient glitch must not break a live session) and returns a zero disk
// credential — no refresh runs there; if the cached token is expired or absent it
// fails closed with errGitLabRefreshDead, so a refresh is never driven off a read
// failure (which would yield an empty snapshot and risk burning the single-use
// refresh token without a durable write-back).
// On a read SUCCESS, local config is the source of truth: if the on-disk host is
// no longer a present OAuth credential (removed, token blanked, or switched to a
// PAT) we stop using the cached token entirely and fail closed, regardless of
// whether the cached token is still valid.
func (s *glabOAuthSource) freshest() (*oauth2.Token, glabCredential, error) {
	cred, err := s.readCreds()
	if err != nil {
		// Read FAILURE only: keep using a still-valid cached token (a transient glitch
		// must not break a live session); else fail closed.
		if s.cached != nil && !tokenExpired(s.cached, s.now()) {
			return s.cached, glabCredential{}, nil //nolint:exhaustruct // valid cached; no disk cred.
		}

		return nil, glabCredential{}, errGitLabRefreshDead //nolint:exhaustruct // dead.
	}
	// Read SUCCESS: local config is the source of truth. If the host is no longer a
	// present OAuth credential (removed, token blanked, or switched to a PAT), stop
	// using the cached OAuth token entirely — fail closed regardless of cache validity.
	if cred.AccessToken == "" || !cred.IsOAuth2 {
		return nil, glabCredential{}, errGitLabRefreshDead //nolint:exhaustruct // local config changed.
	}
	// credToToken(cred) is guaranteed non-nil here (cred.AccessToken != ""); the
	// freshestToken result is also non-nil (at minimum the on-disk token is live).
	tok := freshestToken(s.cached, credToToken(cred))

	return tok, cred, nil
}

// recover runs the bounded invalid_grant recovery loop: on invalid_grant, re-read
// with backoff until the on-disk credential becomes a valid token or the deadline
// expires. A non-invalid_grant error propagates immediately.
func (s *glabOAuthSource) recover(refreshErr error) (*oauth2.Token, error) {
	if !isInvalidGrant(refreshErr) {
		return nil, refreshErr
	}

	deadline := s.now().Add(invalidGrantDeadline)
	for {
		cred, err := s.readCreds()
		if err != nil {
			return nil, fmt.Errorf("gitlab: re-read glab config: %w", err)
		}
		// Local config is the source of truth: adopt ONLY a present, unexpired OAuth
		// credential. A host switched to a PAT (or absent) during recovery is never
		// pulled into the OAuth session — keep waiting and ultimately fail closed.
		if cred.IsOAuth2 && cred.AccessToken != "" {
			if tok := credToToken(cred); !tokenExpired(tok, s.now()) {
				s.cached = tok

				return tok, nil
			}
		}
		if !s.now().Before(deadline) {
			return nil, errGitLabRefreshDead
		}
		s.sleep(invalidGrantBackoff)
	}
}

// isInvalidGrant reports whether err is an OAuth invalid_grant token-endpoint error.
func isInvalidGrant(err error) bool {
	if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok {
		return re.ErrorCode == "invalid_grant"
	}

	return false
}

// adoptOnDiskRotation returns the on-disk token (and true) when cur's refresh
// token is non-empty and differs from diskSnapshotRefresh — a concurrent writer
// rotated the host since our pre-refresh disk read. Comparing against the
// pre-refresh disk snapshot (not the token we refreshed from) avoids resurrecting
// a stale on-disk token after an earlier write-back failure. An empty/unchanged
// refresh token returns (nil, false) so the caller proceeds to write.
func adoptOnDiskRotation(cur glabCredential, diskSnapshotRefresh string) (*oauth2.Token, bool) {
	if cur.AccessToken == "" {
		return nil, false
	}
	if cur.RefreshToken != "" && cur.RefreshToken != diskSnapshotRefresh {
		return credToToken(cur), true
	}

	return nil, false
}
