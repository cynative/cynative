package llm

import (
	"context"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// bifrostShellInit is the real Bifrost SDK constructor. It lives in the
// imperative shell (_shell.go, excluded from the coverage gate) because it
// performs real SDK initialisation that cannot be unit-tested. NewBifrostChatModel
// defaults the BifrostChatModel.newBackend factory field to this function and
// always invokes it; tests inject a fake backend via the WithBackend /
// WithBackendFactory options (export_test.go) instead.
func bifrostShellInit(ctx context.Context, cfg schemas.BifrostConfig) (BifrostBackend, error) {
	return bifrost.Init(ctx, cfg)
}
