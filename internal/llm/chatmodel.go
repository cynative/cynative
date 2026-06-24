package llm

import (
	"context"
	"fmt"

	bifrost "github.com/maximhq/bifrost/core"
	bschemas "github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/schema"
)

// Compile-time assertion: BifrostChatModel implements the internal chat model.
var _ schema.ChatModel = (*BifrostChatModel)(nil)

// BifrostChatModel adapts a BifrostBackend to the internal schema.ChatModel,
// exposing Bifrost's providers to the agent loop through one chat-model interface.
type BifrostChatModel struct {
	backend            BifrostBackend
	newBackend         func(context.Context, bschemas.BifrostConfig) (BifrostBackend, error)
	recordUsage        func(schema.Usage)
	provider           string
	model              string
	reasoningEffort    string
	reasoningMaxTokens int
}

// ChatModelOption configures a BifrostChatModel at construction time.
// WithUsageRecorder (options.go) is the production-facing option wired by the cli
// composition root; the remaining options are test-only (see export_test.go) and
// replace the backend factory.
type ChatModelOption func(*BifrostChatModel)

// NewBifrostChatModel constructs a chat model backed by Bifrost. The backend
// factory defaults to the real SDK constructor (bifrostShellInit, in the
// gate-excluded shell); the factory is always invoked, so tests inject a double
// via the WithBackend* options to cover the success and error paths here.
func NewBifrostChatModel(
	ctx context.Context,
	account *FileAccount,
	opts ...ChatModelOption,
) (*BifrostChatModel, error) {
	m := &BifrostChatModel{ //nolint:exhaustruct // backend set below
		newBackend:         bifrostShellInit,
		recordUsage:        func(schema.Usage) {},
		provider:           account.Entry.Provider,
		model:              account.Entry.Model,
		reasoningEffort:    account.Entry.ReasoningEffort,
		reasoningMaxTokens: account.Entry.ReasoningMaxTokens,
	}
	for _, o := range opts {
		o(m)
	}

	backend, err := m.newBackend(
		ctx,
		bschemas.BifrostConfig{ //nolint:exhaustruct // optional Bifrost fields intentionally omitted
			Account: account,
			Logger:  bifrost.NewDefaultLogger(bschemas.LogLevelWarn),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("bifrost init: %w", err)
	}

	m.backend = backend

	return m, nil
}

// Shutdown releases the underlying Bifrost backend resources.
func (c *BifrostChatModel) Shutdown() { c.backend.Shutdown() }

// buildRequest assembles the Bifrost chat request for Generate. The per-call
// tools argument supplies the tool schemas (nil for a tool-less call), and the
// operator's reasoning config (llm.reasoning_effort / llm.reasoning_max_tokens)
// is attached as Params.Reasoning. Other generation parameters (temperature,
// etc.) are intentionally not exposed.
func (c *BifrostChatModel) buildRequest(
	input []*schema.Message,
	tools []*schema.ToolInfo,
) *bschemas.BifrostChatRequest {
	req := &bschemas.BifrostChatRequest{ //nolint:exhaustruct // optional Bifrost fields intentionally omitted
		Provider: bschemas.ModelProvider(c.provider),
		Model:    c.model,
		Input:    schemaToBifrostMessages(input),
	}

	if params := schemaToolsToParams(tools); params != nil {
		req.Params = params
	}

	if reasoning := c.reasoning(); reasoning != nil {
		if req.Params == nil {
			req.Params = &bschemas.ChatParameters{} //nolint:exhaustruct // only Reasoning set
		}
		req.Params.Reasoning = reasoning
	}

	applyCacheBreakpoints(req)

	return req
}

// reasoning builds the per-request ChatReasoning from the operator's
// llm.reasoning_effort / llm.reasoning_max_tokens config, or returns nil when
// both are unset (the payload then carries no reasoning key at all). A fresh
// value is built per call so requests never share a mutable pointer.
func (c *BifrostChatModel) reasoning() *bschemas.ChatReasoning {
	if c.reasoningEffort == "" && c.reasoningMaxTokens <= 0 {
		return nil
	}

	r := &bschemas.ChatReasoning{} //nolint:exhaustruct // only configured fields set
	if c.reasoningEffort != "" {
		r.Effort = new(c.reasoningEffort)
	}
	if c.reasoningMaxTokens > 0 {
		r.MaxTokens = new(c.reasoningMaxTokens)
	}

	return r
}

// Generate sends a chat completion request and returns the assistant message.
// The per-call tools argument (nil for a tool-less call) is honored via
// buildRequest, which also attaches the operator's reasoning config; other
// generation parameters (temperature, etc.) are intentionally not exposed.
func (c *BifrostChatModel) Generate(
	ctx context.Context,
	input []*schema.Message,
	tools []*schema.ToolInfo,
) (*schema.Message, error) {
	bCtx := bschemas.NewBifrostContext(ctx, bschemas.NoDeadline)
	resp, bErr := c.backend.ChatCompletionRequest(bCtx, c.buildRequest(input, tools))
	if bErr != nil {
		return nil, newGenerateError(bErr)
	}
	if resp == nil || len(resp.Choices) == 0 {
		return nil, &GenerateError{Message: "bifrost returned no choices"} //nolint:exhaustruct // no status/code.
	}
	choice := resp.Choices[0]
	if choice.ChatNonStreamResponseChoice == nil || choice.Message == nil {
		//nolint:exhaustruct // no status/code.
		return nil, &GenerateError{Message: "bifrost returned no message in choice"}
	}

	c.recordUsage(usageFromBifrost(resp.Usage))

	return schemaFromBifrostMessage(*choice.Message), nil
}
