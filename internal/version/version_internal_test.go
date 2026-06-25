package version

import (
	"runtime/debug"
	"testing"
)

// settings builds a []debug.BuildSetting from alternating key/value pairs.
func settings(kv ...string) []debug.BuildSetting {
	out := make([]debug.BuildSetting, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
	}

	return out
}

// buildInfo is a small constructor for a [debug.BuildInfo] test double.
func buildInfo(mainVersion, goVersion string, s []debug.BuildSetting) *debug.BuildInfo {
	bi := &debug.BuildInfo{GoVersion: goVersion, Settings: s} //nolint:exhaustruct // only fields under test.
	bi.Main.Version = mainVersion

	return bi
}

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                        string
		ldVersion, ldCommit, ldDate string
		bi                          *debug.BuildInfo
		goVersion, goos, goarch     string
		want                        Info
	}{
		{
			name:      "ldflags release (commit truncated, dirty ignored on ldflags path)",
			ldVersion: "1.0.0",
			ldCommit:  "1a2b3c4d5e6f7a8b",
			ldDate:    "2026-06-24T10:30:00Z",
			bi:        buildInfo("(devel)", "go1.24.0", settings("vcs.modified", "true")),
			goVersion: "go1.24.0",
			goos:      "linux",
			goarch:    "amd64",
			want: Info{
				Version:   "1.0.0",
				Commit:    "1a2b3c4d5e6f",
				Date:      "2026-06-24T10:30:00Z",
				GoVersion: "go1.24.0",
				Platform:  "linux/amd64",
			},
		},
		{
			name:      "ldflags version with leading v is stripped",
			ldVersion: "v1.2.3",
			ldCommit:  "abc123",
			ldDate:    "2026-01-01T00:00:00Z",
			bi:        nil,
			goVersion: "go1.24.0",
			goos:      "darwin",
			goarch:    "arm64",
			want: Info{
				Version:   "1.2.3",
				Commit:    "abc123",
				Date:      "2026-01-01T00:00:00Z",
				GoVersion: "go1.24.0",
				Platform:  "darwin/arm64",
			},
		},
		{
			name:      "go install module version, no vcs settings",
			ldVersion: "",
			ldCommit:  "",
			ldDate:    "",
			bi:        buildInfo("v1.0.0", "go1.24.0", nil),
			goVersion: "go1.24.0",
			goos:      "linux",
			goarch:    "amd64",
			want: Info{
				Version:   "1.0.0",
				Commit:    "none",
				Date:      "unknown",
				GoVersion: "go1.24.0",
				Platform:  "linux/amd64",
			},
		},
		{
			name:      "local dirty build: (devel) -> dev, vcs revision truncated + dirty",
			ldVersion: "dev",
			ldCommit:  "",
			bi: buildInfo("(devel)", "go1.24.0", settings(
				"vcs.revision", "9f8e7d6c5b4a3210fedcba9876543210deadbeef",
				"vcs.time", "2026-06-23T22:05:00Z",
				"vcs.modified", "true",
			)),
			goVersion: "go1.24.0",
			goos:      "linux",
			goarch:    "amd64",
			want: Info{
				Version:   "dev",
				Commit:    "9f8e7d6c5b4a+dirty",
				Date:      "2026-06-23T22:05:00Z",
				GoVersion: "go1.24.0",
				Platform:  "linux/amd64",
			},
		},
		{
			name:      "local clean build: vcs.modified false -> no dirty suffix",
			ldVersion: "",
			ldCommit:  "",
			bi: buildInfo("(devel)", "go1.24.0", settings(
				"vcs.revision", "9f8e7d6c5b4a3210fedcba9876543210deadbeef",
				"vcs.modified", "false",
			)),
			goVersion: "go1.24.0",
			goos:      "linux",
			goarch:    "amd64",
			want: Info{
				Version:   "dev",
				Commit:    "9f8e7d6c5b4a",
				Date:      "unknown",
				GoVersion: "go1.24.0",
				Platform:  "linux/amd64",
			},
		},
		{
			name:      "revision present, vcs.modified absent entirely -> no dirty, date from vcs.time",
			ldVersion: "",
			ldCommit:  "",
			bi: buildInfo("(devel)", "go1.24.0", settings(
				"vcs.revision", "0123456789abcdef0123456789abcdef01234567",
				"vcs.time", "2026-05-01T00:00:00Z",
			)),
			goVersion: "go1.24.0",
			goos:      "linux",
			goarch:    "amd64",
			want: Info{
				Version:   "dev",
				Commit:    "0123456789ab",
				Date:      "2026-05-01T00:00:00Z",
				GoVersion: "go1.24.0",
				Platform:  "linux/amd64",
			},
		},
		{
			name:      "ldCommit set + vcs.modified true -> bare ldCommit, NO dirty (gating pinned)",
			ldVersion: "2.0.0",
			ldCommit:  "feedface0000111122223333444455556666",
			bi:        buildInfo("(devel)", "go1.24.0", settings("vcs.modified", "true")),
			goVersion: "go1.24.0",
			goos:      "linux",
			goarch:    "amd64",
			want: Info{
				Version:   "2.0.0",
				Commit:    "feedface0000",
				Date:      "unknown",
				GoVersion: "go1.24.0",
				Platform:  "linux/amd64",
			},
		},
		{
			name:      "empty ldVersion + nil build info -> dev/none/unknown, goVersion fallback",
			ldVersion: "",
			ldCommit:  "",
			ldDate:    "",
			bi:        nil,
			goVersion: "go1.24.0",
			goos:      "windows",
			goarch:    "amd64",
			want: Info{
				Version:   "dev",
				Commit:    "none",
				Date:      "unknown",
				GoVersion: "go1.24.0",
				Platform:  "windows/amd64",
			},
		},
		{
			name:      "non-nil build info with empty GoVersion -> passed goVersion",
			ldVersion: "3.1.4",
			ldCommit:  "cafe",
			ldDate:    "2026-03-14T00:00:00Z",
			bi:        buildInfo("(devel)", "", nil),
			goVersion: "go1.99.0",
			goos:      "linux",
			goarch:    "arm64",
			want: Info{
				Version:   "3.1.4",
				Commit:    "cafe",
				Date:      "2026-03-14T00:00:00Z",
				GoVersion: "go1.99.0",
				Platform:  "linux/arm64",
			},
		},
		{
			name:      "settings present but queried keys absent -> commit none, date unknown",
			ldVersion: "", ldCommit: "",
			bi:        buildInfo("(devel)", "go1.24.0", settings("GOOS", "linux", "GOARCH", "amd64")),
			goVersion: "go1.24.0", goos: "linux", goarch: "amd64",
			want: Info{Version: "dev", Commit: "none", Date: "unknown", GoVersion: "go1.24.0", Platform: "linux/amd64"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := Resolve(tc.ldVersion, tc.ldCommit, tc.ldDate, tc.bi, tc.goVersion, tc.goos, tc.goarch)
			if got != tc.want {
				t.Errorf("Resolve()\n got = %+v\nwant = %+v", got, tc.want)
			}
		})
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()

	info := Info{
		Version:   "1.0.0",
		Commit:    "1a2b3c4d5e6f",
		Date:      "2026-06-24T10:30:00Z",
		GoVersion: "go1.24.0",
		Platform:  "linux/amd64",
	}

	want := "cynative 1.0.0\n" +
		"  commit:   1a2b3c4d5e6f\n" +
		"  built:    2026-06-24T10:30:00Z\n" +
		"  go:       go1.24.0\n" +
		"  platform: linux/amd64"

	if got := info.String(); got != want {
		t.Errorf("String()\n got = %q\nwant = %q", got, want)
	}
}
