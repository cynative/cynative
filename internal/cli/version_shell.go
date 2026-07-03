package cli

import (
	"fmt"
	"runtime"
)

// version, commit, and date are stamped at link time via `-ldflags -X` (goreleaser
// for releases). They are immutable after link; declared as vars only because -X can
// patch only package-level string vars. Dev builds keep these defaults, so
// `go build ./cmd/cynative` reports dev/none/unknown.
//
//nolint:gochecknoglobals // link-time build stamps set via -ldflags -X; never mutated at runtime.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionString renders the multi-line --version output without a trailing newline
// (the cobra version template adds the final newline). It preserves all five
// documented fields — version, commit, build date, Go version, platform — aligned at
// one column.
func versionString() string {
	return fmt.Sprintf(
		"cynative %s\n"+
			"  commit:   %s\n"+
			"  built:    %s\n"+
			"  go:       %s\n"+
			"  platform: %s/%s",
		version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH,
	)
}
