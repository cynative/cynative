// Package version resolves and renders the cynative build metadata reported by
// the --version flag.
package version

import (
	"runtime/debug"
	"strings"
)

// shortCommitLen is the number of leading hex characters of a commit SHA kept for
// display. Twelve is collision-safe for a project of this size while staying compact.
const shortCommitLen = 12

// Info is the resolved build metadata rendered by the --version flag.
type Info struct {
	Version   string // e.g. "1.0.0" or "dev".
	Commit    string // short commit, "+dirty" when built from a modified worktree, or "none".
	Date      string // RFC3339 build/commit time, or "unknown".
	GoVersion string // e.g. "go1.24.0".
	Platform  string // e.g. "linux/amd64".
}

// Resolve applies the fallback chain from the ldflags-injected strings and the
// runtime build info to a fully-populated Info. bi may be nil (when
// [debug.ReadBuildInfo] reported ok == false); every build-info read is nil-guarded.
func Resolve(
	ldVersion, ldCommit, ldDate string,
	bi *debug.BuildInfo,
	goVersion, goos, goarch string,
) Info {
	return Info{
		Version:   resolveVersion(ldVersion, bi),
		Commit:    resolveCommit(ldCommit, bi),
		Date:      resolveDate(ldDate, bi),
		GoVersion: resolveGoVersion(goVersion, bi),
		Platform:  goos + "/" + goarch,
	}
}

// resolveVersion prefers a real ldflags stamp, then the module version, then "dev",
// stripping a single leading "v" uniformly for a consistent display.
func resolveVersion(ldVersion string, bi *debug.BuildInfo) string {
	v := "dev"

	switch {
	case ldVersion != "" && ldVersion != "dev":
		v = ldVersion
	case bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)":
		v = bi.Main.Version
	}

	return strings.TrimPrefix(v, "v")
}

// resolveCommit prefers the ldflags stamp (release builds tag a clean tree, so it
// never gets a +dirty suffix), else the vcs.revision setting with +dirty when the
// worktree was modified, else "none". The commit is always shortened.
func resolveCommit(ldCommit string, bi *debug.BuildInfo) string {
	if ldCommit != "" {
		return shortCommit(ldCommit)
	}

	rev := buildSetting(bi, "vcs.revision")
	if rev == "" {
		return "none"
	}

	c := shortCommit(rev)
	if buildSetting(bi, "vcs.modified") == "true" {
		c += "+dirty"
	}

	return c
}

// resolveDate prefers the ldflags stamp, then the vcs.time setting, then "unknown".
func resolveDate(ldDate string, bi *debug.BuildInfo) string {
	if ldDate != "" {
		return ldDate
	}
	if t := buildSetting(bi, "vcs.time"); t != "" {
		return t
	}

	return "unknown"
}

// resolveGoVersion prefers the build info's Go version, else the passed runtime value.
func resolveGoVersion(goVersion string, bi *debug.BuildInfo) string {
	if bi != nil && bi.GoVersion != "" {
		return bi.GoVersion
	}

	return goVersion
}

// buildSetting returns the value of a [debug.BuildInfo] setting, or "" when bi is nil
// or the key is absent.
func buildSetting(bi *debug.BuildInfo, key string) string {
	if bi == nil {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}

	return ""
}

// shortCommit truncates a commit SHA to shortCommitLen characters for display.
func shortCommit(c string) string {
	if len(c) > shortCommitLen {
		return c[:shortCommitLen]
	}

	return c
}

// String renders the multi-line --version output without a trailing newline (the
// cobra version template adds the final newline). Values align at one column.
func (i Info) String() string {
	var b strings.Builder

	b.WriteString("cynative " + i.Version + "\n")
	b.WriteString("  commit:   " + i.Commit + "\n")
	b.WriteString("  built:    " + i.Date + "\n")
	b.WriteString("  go:       " + i.GoVersion + "\n")
	b.WriteString("  platform: " + i.Platform)

	return b.String()
}
