package llm_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	bschemas "github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
	"github.com/cynative/cynative/internal/metrics"
	"github.com/cynative/cynative/internal/schema"
)

// testAccount builds a minimal FileAccount for chat-model tests. Key.Value is a
// bschemas.SecretVar, so a literal key is built via newLiteralKey (account_test.go).
func testAccount() *llm.FileAccount {
	return &llm.FileAccount{
		Entry: llm.ProviderEntry{ //nolint:exhaustruct // only the fields under test populated
			Provider: "openai",
			Model:    "gpt-4o",
			Keys:     []bschemas.Key{newLiteralKey("k", "k")},
		},
	}
}

// TestBifrostChatModel_Generate verifies a non-streaming assistant response is returned.
func TestBifrostChatModel_Generate(t *testing.T) {
	t.Parallel()

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return assistantResp("hello back"), nil
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	out, err := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out.Text() != "hello back" {
		t.Errorf("content = %q, want %q", out.Text(), "hello back")
	}
	if out.Role != schema.Assistant {
		t.Errorf("role = %q, want %q", out.Role, schema.Assistant)
	}
	// The request must carry the configured provider and model.
	calls := mock.ChatCompletionRequestCalls()
	if len(calls) == 0 {
		t.Fatal("no ChatCompletionRequest calls recorded")
	}
	req := calls[0].Req
	if string(req.Provider) != "openai" || req.Model != "gpt-4o" {
		t.Errorf("request provider/model = %q/%q, want openai/gpt-4o", req.Provider, req.Model)
	}
}

// TestBifrostChatModel_GenerateError verifies a backend error surfaces as a
// typed *GenerateError wrapping ErrGenerate, with status code and code fields.
func TestBifrostChatModel_GenerateError(t *testing.T) {
	t.Parallel()

	status := http.StatusUnauthorized
	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return nil, &bschemas.BifrostError{ //nolint:exhaustruct // only the fields under test.
				StatusCode: &status,
				Error: &bschemas.ErrorField{ //nolint:exhaustruct // only the fields under test.
					Code:    new("invalid_api_key"),
					Message: "upstream failure",
				},
			}
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	_, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)
	if !errors.Is(err, llm.ErrGenerate) {
		t.Fatalf("error = %v, want errors.Is ErrGenerate", err)
	}
	var ge *llm.GenerateError
	if !errors.As(err, &ge) || ge.StatusCode != http.StatusUnauthorized || ge.Code != "invalid_api_key" {
		t.Errorf("GenerateError fields lost: %#v", ge)
	}
}

// TestBifrostChatModel_GenerateErrorNilStatusCode verifies a backend error with
// nil StatusCode and nil Error surfaces correctly as a *GenerateError with zero
// status code and empty code.
func TestBifrostChatModel_GenerateErrorNilStatusCode(t *testing.T) {
	t.Parallel()

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return nil, &bschemas.BifrostError{ //nolint:exhaustruct // StatusCode and Error are nil.
				Error: nil,
			}
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	_, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)
	if !errors.Is(err, llm.ErrGenerate) {
		t.Fatalf("error = %v, want errors.Is ErrGenerate", err)
	}
	var ge *llm.GenerateError
	if !errors.As(err, &ge) {
		t.Fatalf("errors.As failed: %v", err)
	}
	if ge.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0", ge.StatusCode)
	}
	if ge.Code != "" {
		t.Errorf("Code = %q, want empty string", ge.Code)
	}
	if ge.Message == "" {
		t.Error("Message is empty, expected non-empty")
	}
}

// TestBifrostChatModel_GenerateErrorNilCode verifies a backend error with nil
// StatusCode and nil Code field surfaces correctly as a *GenerateError with zero
// status code and empty code. This covers the common network-error case.
func TestBifrostChatModel_GenerateErrorNilCode(t *testing.T) {
	t.Parallel()

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return nil, &bschemas.BifrostError{ //nolint:exhaustruct // StatusCode and Error.Code are nil.
				StatusCode: nil,
				Error: &bschemas.ErrorField{ //nolint:exhaustruct // Code is nil.
					Code:    nil,
					Message: "network unreachable",
				},
			}
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	_, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)
	if !errors.Is(err, llm.ErrGenerate) {
		t.Fatalf("error = %v, want errors.Is ErrGenerate", err)
	}
	var ge *llm.GenerateError
	if !errors.As(err, &ge) {
		t.Fatalf("errors.As failed: %v", err)
	}
	if ge.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0", ge.StatusCode)
	}
	if ge.Code != "" {
		t.Errorf("Code = %q, want empty string", ge.Code)
	}
	if ge.Message == "" {
		t.Error("Message is empty, expected non-empty")
	}
}

// TestBifrostChatModel_GenerateNoChoices verifies an empty Choices slice errors.
func TestBifrostChatModel_GenerateNoChoices(t *testing.T) {
	t.Parallel()

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return &bschemas.BifrostChatResponse{ //nolint:exhaustruct // empty choices
				Choices: []bschemas.BifrostResponseChoice{},
			}, nil
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	_, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)
	if err == nil {
		t.Fatal("expected error for empty choices, got nil")
	}
	if !strings.Contains(err.Error(), "no choices") {
		t.Errorf("error = %v, want 'no choices'", err)
	}
}

// TestBifrostChatModel_GenerateNilChoiceMessage verifies a choice with a nil
// ChatNonStreamResponseChoice/Message errors.
func TestBifrostChatModel_GenerateNilChoiceMessage(t *testing.T) {
	t.Parallel()

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return &bschemas.BifrostChatResponse{ //nolint:exhaustruct // nil message in choice
				Choices: []bschemas.BifrostResponseChoice{
					{}, //nolint:exhaustruct // ChatNonStreamResponseChoice is nil to trigger the error
				},
			}, nil
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	_, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)
	if err == nil {
		t.Fatal("expected error for nil choice message, got nil")
	}
	if !strings.Contains(err.Error(), "no message") {
		t.Errorf("error = %v, want 'no message'", err)
	}
}

// TestBifrostChatModel_Shutdown verifies Shutdown is delegated to the backend.
func TestBifrostChatModel_Shutdown(t *testing.T) {
	t.Parallel()

	shutdownCalled := false
	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return assistantResp("ok"), nil
		},
		ShutdownFunc: func() { shutdownCalled = true },
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}
	m.Shutdown()
	if !shutdownCalled {
		t.Error("expected backend.Shutdown() to be called")
	}
}

// TestBifrostChatModel_GenerateHonorsTools verifies tools supplied via the
// per-call tools argument reach the request.
func TestBifrostChatModel_GenerateHonorsTools(t *testing.T) {
	t.Parallel()

	var lastReq *bschemas.BifrostChatRequest
	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, req *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			lastReq = req
			return assistantResp("ok"), nil
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	_, err = m.Generate(
		context.Background(),
		[]*schema.Message{schema.UserMessage("hi")},
		[]*schema.ToolInfo{
			{Name: "http_request", Desc: "make a request"}, //nolint:exhaustruct // only Name/Desc
		},
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if lastReq.Params == nil || len(lastReq.Params.Tools) != 1 {
		t.Fatalf("tools not carried: %+v", lastReq.Params)
	}
	if lastReq.Params.Tools[0].Function == nil || lastReq.Params.Tools[0].Function.Name != "http_request" {
		t.Errorf("tool name not carried: %+v", lastReq.Params.Tools[0])
	}
	if lastReq.Params.Reasoning != nil {
		t.Errorf("Reasoning = %+v, want nil when reasoning config is unset", lastReq.Params.Reasoning)
	}
}

// TestBifrostChatModel_RecordsUsage verifies Generate reports the response's
// token usage to the injected recordUsage sink.
func TestBifrostChatModel_RecordsUsage(t *testing.T) {
	t.Parallel()

	resp := assistantResp("ok")
	resp.Usage = &bschemas.BifrostLLMUsage{ //nolint:exhaustruct // only the mapped fields.
		PromptTokens:     30,
		CompletionTokens: 7,
		TotalTokens:      37,
	}

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set.
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return resp, nil
		},
		ShutdownFunc: func() {},
	}

	var got schema.Usage
	m, err := llm.NewBifrostChatModel(
		context.Background(),
		testAccount(),
		llm.WithBackend(mock),
		llm.WithUsageRecorder(func(u schema.Usage) { got = u }),
	)
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	if _, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got.PromptTokens != 30 || got.CompletionTokens != 7 || got.TotalTokens != 37 {
		t.Errorf("recorded usage = %+v, want 30/7/37", got)
	}
}

func TestWithUsageRecorder_NilIgnored(t *testing.T) {
	t.Parallel()

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs.
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return assistantResp("ok"), nil
		},
		ShutdownFunc: func() {},
	}
	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(),
		llm.WithBackend(mock), llm.WithUsageRecorder(nil))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}
	// A nil sink leaves the no-op default in place; Generate must not panic.
	if _, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}
}

// reasoningAccount returns a testAccount whose entry carries the given
// reasoning configuration.
func reasoningAccount(effort string, maxTokens int) *llm.FileAccount {
	a := testAccount()
	a.Entry.ReasoningEffort = effort
	a.Entry.ReasoningMaxTokens = maxTokens

	return a
}

// captureBackend returns a mock backend that records every request it sees.
// The slice is appended without locking, so it is for sequential Generate
// calls only.
func captureBackend(reqs *[]*bschemas.BifrostChatRequest) *llm.BifrostBackendMock {
	return &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, req *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			*reqs = append(*reqs, req)
			return assistantResp("ok"), nil
		},
		ShutdownFunc: func() {},
	}
}

// TestBifrostChatModel_NoReasoning_NoParams verifies an unset reasoning config
// leaves the request payload unchanged: with no tools bound, Params stays nil.
func TestBifrostChatModel_NoReasoning_NoParams(t *testing.T) {
	t.Parallel()

	var reqs []*bschemas.BifrostChatRequest
	m, err := llm.NewBifrostChatModel(
		context.Background(),
		testAccount(),
		llm.WithBackend(captureBackend(&reqs)),
	)
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	if _, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if reqs[0].Params != nil {
		t.Errorf("Params = %+v, want nil when reasoning and tools are unset", reqs[0].Params)
	}
}

// TestBifrostChatModel_ReasoningEffortOnly verifies an effort-only config is
// attached even when no tools are bound.
func TestBifrostChatModel_ReasoningEffortOnly(t *testing.T) {
	t.Parallel()

	var reqs []*bschemas.BifrostChatRequest
	m, err := llm.NewBifrostChatModel(
		context.Background(), reasoningAccount("high", 0), llm.WithBackend(captureBackend(&reqs)))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	if _, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r := reqs[0].Params.Reasoning
	if r == nil || r.Effort == nil || *r.Effort != "high" {
		t.Fatalf("Reasoning = %+v, want Effort \"high\"", r)
	}
	if r.MaxTokens != nil {
		t.Errorf("MaxTokens = %v, want nil when unset", *r.MaxTokens)
	}
}

// TestBifrostChatModel_ReasoningMaxTokensOnly verifies a budget-only config is
// attached with no effort field.
func TestBifrostChatModel_ReasoningMaxTokensOnly(t *testing.T) {
	t.Parallel()

	var reqs []*bschemas.BifrostChatRequest
	m, err := llm.NewBifrostChatModel(
		context.Background(), reasoningAccount("", 2048), llm.WithBackend(captureBackend(&reqs)))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	if _, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r := reqs[0].Params.Reasoning
	if r == nil || r.MaxTokens == nil || *r.MaxTokens != 2048 {
		t.Fatalf("Reasoning = %+v, want MaxTokens 2048", r)
	}
	if r.Effort != nil {
		t.Errorf("Effort = %v, want nil when unset", *r.Effort)
	}
}

// TestBifrostChatModel_ReasoningTools_FreshPerCall verifies reasoning
// coexists with bound tools and that each request gets a fresh ChatReasoning
// value (no shared mutable pointer across calls).
func TestBifrostChatModel_ReasoningTools_FreshPerCall(t *testing.T) {
	t.Parallel()

	var reqs []*bschemas.BifrostChatRequest
	m, err := llm.NewBifrostChatModel(
		context.Background(), reasoningAccount("low", 1024), llm.WithBackend(captureBackend(&reqs)))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	tools := []*schema.ToolInfo{
		{Name: "http_request", Desc: "make a request"}, //nolint:exhaustruct // only Name/Desc
	}
	for range 2 {
		if _, err = m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, tools); err != nil {
			t.Fatalf("Generate: %v", err)
		}
	}

	for i, req := range reqs {
		if len(req.Params.Tools) != 1 {
			t.Fatalf("request %d lost its tools: %+v", i, req.Params)
		}
		r := req.Params.Reasoning
		if r == nil || r.Effort == nil || *r.Effort != "low" || r.MaxTokens == nil || *r.MaxTokens != 1024 {
			t.Fatalf("request %d Reasoning = %+v, want low/1024", i, r)
		}
	}
	if reqs[0].Params.Reasoning == reqs[1].Params.Reasoning {
		t.Error("requests share one *ChatReasoning; want a fresh value per call")
	}
}

// TestBifrostChatModel_GenerateMarksCacheBreakpoints verifies buildRequest wires
// applyCacheBreakpoints end to end: the request reaching the backend carries
// ephemeral cache markers on the last tool and on the system + trailing messages.
func TestBifrostChatModel_GenerateMarksCacheBreakpoints(t *testing.T) {
	t.Parallel()

	var lastReq *bschemas.BifrostChatRequest
	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, req *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			lastReq = req
			return assistantResp("ok"), nil
		},
		ShutdownFunc: func() {},
	}

	m, err := llm.NewBifrostChatModel(context.Background(), testAccount(), llm.WithBackend(mock))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	_, err = m.Generate(
		context.Background(),
		[]*schema.Message{
			schema.SystemMessage("sys"),
			schema.UserMessage("hi"),
		},
		[]*schema.ToolInfo{
			{Name: "http_request", Desc: "make a request"}, //nolint:exhaustruct // only Name/Desc
		},
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tools := lastReq.Params.Tools
	if len(tools) != 1 || tools[0].CacheControl == nil ||
		tools[0].CacheControl.Type != bschemas.CacheControlTypeEphemeral {
		t.Fatalf("last tool not cache-marked: %+v", tools)
	}
	for i := range lastReq.Input {
		content := lastReq.Input[i].Content
		if content == nil || len(content.ContentBlocks) != 1 || content.ContentBlocks[0].CacheControl == nil {
			t.Errorf("message %d not cache-marked: %+v", i, content)
		}
	}
}

// TestBifrostChatModel_ConcurrentGenerate pins the concurrency contract the
// agent's verifier panel relies on: concurrent Generate calls must not deadlock,
// race on the usage sink, or return wrong results.
func TestBifrostChatModel_ConcurrentGenerate(t *testing.T) {
	t.Parallel()

	mock := &llm.BifrostBackendMock{ //nolint:exhaustruct // only needed funcs set
		ChatCompletionRequestFunc: func(_ *bschemas.BifrostContext, _ *bschemas.BifrostChatRequest) (*bschemas.BifrostChatResponse, *bschemas.BifrostError) {
			return assistantResp("ok"), nil
		},
		ShutdownFunc: func() {},
	}

	acc := metrics.NewAccumulator("p", "m")
	acc.StartTurn()

	m, err := llm.NewBifrostChatModel(
		context.Background(),
		testAccount(),
		llm.WithBackend(mock),
		llm.WithUsageRecorder(acc.AddUsage),
	)
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	const callers = 8

	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			out, gerr := m.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}, nil)
			if gerr != nil || out.Text() != "ok" {
				t.Errorf("concurrent Generate = (%v, %v)", out, gerr)
			}
		})
	}
	wg.Wait()
}
