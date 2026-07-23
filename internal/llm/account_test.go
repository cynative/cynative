package llm_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

func TestProviderEntry_HoistsEveryKeyConfig(t *testing.T) {
	t.Parallel()

	keyType := reflect.TypeFor[schemas.Key]()
	entryType := reflect.TypeFor[llm.ProviderEntry]()

	for f := range keyType.Fields() {
		if !strings.HasSuffix(f.Name, "KeyConfig") {
			continue
		}
		found := false
		for ef := range entryType.Fields() {
			if ef.Type == f.Type {
				found = true

				break
			}
		}
		if !found {
			t.Errorf("schemas.Key.%s (%s) has no hoisted field of that type on ProviderEntry", f.Name, f.Type)
		}
	}
}

func TestFileAccount_GetConfiguredProviders(t *testing.T) {
	t.Parallel()

	acc := &llm.FileAccount{
		Entry: llm.ProviderEntry{ //nolint:exhaustruct // only Provider populated for this test
			Provider: "openai",
		},
	}
	got, err := acc.GetConfiguredProviders()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []schemas.ModelProvider{"openai"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFileAccount_GetConfigForProvider_Default(t *testing.T) {
	t.Parallel()

	acc := &llm.FileAccount{Entry: llm.ProviderEntry{ //nolint:exhaustruct // only Provider populated
		Provider: "openai",
	}}
	cfg, err := acc.GetConfigForProvider("openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil ProviderConfig")
		// Unreachable (t.Fatal ends the test), but it keeps the nil branch from
		// flowing into the dereference below, which SA5011 otherwise reads as an
		// unguarded deref. Do not drop it.
		return
	}
	if cfg.NetworkConfig.DefaultRequestTimeoutInSeconds != 300 {
		t.Errorf(
			"Timeout: got %d, want 300 (cynative default, not Bifrost's 30s)",
			cfg.NetworkConfig.DefaultRequestTimeoutInSeconds,
		)
	}
	if cfg.ConcurrencyAndBufferSize.Concurrency == 0 {
		t.Error("expected non-zero default concurrency (CheckAndSetDefaults not run)")
	}
}

func TestFileAccount_GetConfigForProvider_WithNetworkConfig(t *testing.T) {
	t.Parallel()

	acc := &llm.FileAccount{Entry: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
		Provider: "vllm-local",
		ProviderConfig: schemas.ProviderConfig{ //nolint:exhaustruct // only NetworkConfig populated
			NetworkConfig: schemas.NetworkConfig{ //nolint:exhaustruct // only BaseURL + Timeout populated
				BaseURL:                        "http://vllm:8000",
				DefaultRequestTimeoutInSeconds: 60,
			},
		},
	}}
	cfg, err := acc.GetConfigForProvider("vllm-local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.NetworkConfig.BaseURL != "http://vllm:8000" {
		t.Errorf("BaseURL: got %q, want http://vllm:8000", cfg.NetworkConfig.BaseURL)
	}
	if cfg.NetworkConfig.DefaultRequestTimeoutInSeconds != 60 {
		t.Errorf("Timeout: got %d, want 60", cfg.NetworkConfig.DefaultRequestTimeoutInSeconds)
	}
}

func TestFileAccount_GetConfigForProvider_Mismatch(t *testing.T) {
	t.Parallel()

	acc := &llm.FileAccount{Entry: llm.ProviderEntry{ //nolint:exhaustruct // only Provider populated
		Provider: "openai",
	}}
	_, err := acc.GetConfigForProvider("anthropic")
	if !errors.Is(err, llm.ErrProviderNotConfigured) {
		t.Errorf("got %v, want ErrProviderNotConfigured", err)
	}
}

func TestFileAccount_GetKeysForProvider_HappyPath(t *testing.T) {
	t.Parallel()

	acc := &llm.FileAccount{Entry: llm.ProviderEntry{ //nolint:exhaustruct // only fields under test populated
		Provider: "openai",
		Keys: []schemas.Key{
			newLiteralKey("k1", "sk-test"),
			newLiteralKey("k2", "literal-key"),
		},
	}}
	keys, err := acc.GetKeysForProvider(context.Background(), "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].Value.Val != "sk-test" {
		t.Errorf("key[0].Value.Val: got %q, want sk-test", keys[0].Value.Val)
	}
}

func TestFileAccount_GetKeysForProvider_Mismatch(t *testing.T) {
	t.Parallel()

	acc := &llm.FileAccount{Entry: llm.ProviderEntry{ //nolint:exhaustruct // only Provider populated
		Provider: "openai",
	}}
	_, err := acc.GetKeysForProvider(context.Background(), "anthropic")
	if !errors.Is(err, llm.ErrProviderNotConfigured) {
		t.Errorf("got %v, want ErrProviderNotConfigured", err)
	}
}

func TestFileAccount_GetKeysForProvider_NoKeys(t *testing.T) {
	t.Parallel()

	acc := &llm.FileAccount{Entry: llm.ProviderEntry{ //nolint:exhaustruct // Keys intentionally nil
		Provider: "openai",
	}}
	_, err := acc.GetKeysForProvider(context.Background(), "openai")
	if !errors.Is(err, llm.ErrNoKeysForProvider) {
		t.Errorf("got %v, want ErrNoKeysForProvider", err)
	}
}

// newLiteralKey builds a schemas.Key with a literal (non-env) value for tests.
func newLiteralKey(name, value string) schemas.Key {
	return schemas.Key{ //nolint:exhaustruct // optional Bifrost fields intentionally omitted
		ID:     name,
		Name:   name,
		Value:  schemas.SecretVar{Val: value},
		Models: schemas.WhiteList{"*"},
		Weight: 1.0,
	}
}

// Compile-time check: FileAccount satisfies schemas.Account.
var _ schemas.Account = (*llm.FileAccount)(nil)
