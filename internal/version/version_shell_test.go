package version_test

import (
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/version"
)

func TestGet(t *testing.T) {
	t.Parallel()

	info := version.Get()

	if info.Version == "" {
		t.Error("Version must not be empty (defaults to \"dev\" under go test)")
	}
	if info.GoVersion == "" {
		t.Error("GoVersion must not be empty")
	}
	if !strings.Contains(info.Platform, "/") {
		t.Errorf("Platform = %q, want a goos/goarch form", info.Platform)
	}
	// String must render without panicking and start with the wordmark prefix.
	if !strings.HasPrefix(info.String(), "cynative ") {
		t.Errorf("String() = %q, want it to start with \"cynative \"", info.String())
	}
}
