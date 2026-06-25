package version

import (
	"runtime"
	"runtime/debug"
)

// version, commit, and date are stamped at link time via `-ldflags -X` (goreleaser
// for releases). They are immutable after link; declared as vars only because -X can
// patch only package-level string vars.
//
//nolint:gochecknoglobals // link-time build stamps set via -ldflags -X; never mutated at runtime.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// Get reads the runtime build info and resolves the build metadata. [debug.ReadBuildInfo]
// returns (nil, false) together, so the ok bool is discarded — a nil bi already
// encodes "no build info" for Resolve.
func Get() Info {
	bi, _ := debug.ReadBuildInfo()

	return Resolve(version, commit, date, bi, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
