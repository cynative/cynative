package llm

import (
	"context"
	"errors"
	"testing"

	bschemas "github.com/maximhq/bifrost/core/schemas"
)

// TestNewBifrostChatModel_BackendInitError covers the error path: when the
// backend factory fails, NewBifrostChatModel propagates the wrapped error.
func TestNewBifrostChatModel_BackendInitError(t *testing.T) {
	t.Parallel()

	initErr := errors.New("init failed")

	_, err := NewBifrostChatModel(context.Background(), &FileAccount{ //nolint:exhaustruct // minimal account
		Entry: ProviderEntry{ //nolint:exhaustruct // only required fields
			Provider: "openai",
			Model:    "gpt-4o",
		},
	}, WithBackendFactory(func(context.Context, bschemas.BifrostConfig) (BifrostBackend, error) {
		return nil, initErr
	}))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, initErr) {
		t.Errorf("error = %v, want to wrap %v", err, initErr)
	}
}

// TestNewBifrostChatModel_BackendInitSuccess covers the success path: the factory
// result is wired as the model's backend.
func TestNewBifrostChatModel_BackendInitSuccess(t *testing.T) {
	t.Parallel()

	stub := &BifrostBackendMock{ //nolint:exhaustruct // only Shutdown needed for this test
		ShutdownFunc: func() {},
	}

	m, err := NewBifrostChatModel(context.Background(), &FileAccount{ //nolint:exhaustruct // minimal account
		Entry: ProviderEntry{ //nolint:exhaustruct // only required fields
			Provider: "openai",
			Model:    "gpt-4o",
		},
	}, WithBackend(stub))
	if err != nil {
		t.Fatalf("NewBifrostChatModel: %v", err)
	}

	m.Shutdown()

	if len(stub.ShutdownCalls()) != 1 {
		t.Errorf("Shutdown calls = %d, want 1", len(stub.ShutdownCalls()))
	}
}
