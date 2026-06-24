package llm

import (
	"github.com/maximhq/bifrost/core/schemas"
)

// BifrostBackend is the subset of bifrost.Bifrost we depend on. Defined as
// an interface so tests can substitute a fake.
//
//go:generate go tool moq -out bifrost_mock_test.go . BifrostBackend
type BifrostBackend interface {
	// ChatCompletionRequest sends a chat completion request to Bifrost. Must be
	// safe for concurrent use (Bifrost is a concurrent gateway; the verifier
	// panel fans out requests).
	ChatCompletionRequest(
		ctx *schemas.BifrostContext,
		req *schemas.BifrostChatRequest,
	) (*schemas.BifrostChatResponse, *schemas.BifrostError)
	// Shutdown releases backend resources.
	Shutdown()
}
