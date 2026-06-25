package llm_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

// Compile-time pin: ValidateEnvVars and EnvSecretVar depend on this schemas.SecretVar
// API surface — the exported Val field, the NewSecretVar constructor, and the
// IsFromEnv/GetValue/EnvKey methods. If Bifrost renames any of them in a future
// version, these declarations fail the build instead of silently regressing
// env-var validation at runtime.
var (
	_                                 = schemas.SecretVar{Val: ""}
	_ func(string) *schemas.SecretVar = schemas.NewSecretVar
	_ func(*schemas.SecretVar) bool   = (*schemas.SecretVar).IsFromEnv
	_ func(*schemas.SecretVar) string = (*schemas.SecretVar).GetValue
	_ func(*schemas.SecretVar) string = (*schemas.SecretVar).EnvKey
)

func TestValidateEnvVars_NoEnvVars(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "openai",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "k",
			Value:  schemas.SecretVar{Val: "literal"},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
		}},
	}
	if err := llm.ValidateEnvVars(&entry); err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

func TestValidateEnvVars_ResolvedEnvVar(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "openai",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "k",
			Value:  llm.EnvSecretVar("env.OPENAI_KEY", "resolved"),
			Models: schemas.WhiteList{"*"},
			Weight: 1,
		}},
	}
	if err := llm.ValidateEnvVars(&entry); err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

func TestValidateEnvVars_UnsetEnvVar(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "openai",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "k",
			Value:  llm.EnvSecretVar("env.UNSET_OPENAI", ""),
			Models: schemas.WhiteList{"*"},
			Weight: 1,
		}},
	}
	err := llm.ValidateEnvVars(&entry)
	if !errors.Is(err, llm.ErrEnvVarUnset) {
		t.Errorf("got %v, want ErrEnvVarUnset", err)
	}
	if !strings.Contains(err.Error(), "UNSET_OPENAI") {
		t.Errorf("error message should name UNSET_OPENAI, got: %v", err)
	}
}

func TestValidateEnvVars_NestedStructEnvVar(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "vertex",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "sa",
			Value:  schemas.SecretVar{Val: "literal"},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
			VertexKeyConfig: &schemas.VertexKeyConfig{
				ProjectID:       schemas.SecretVar{Val: "p"},
				AuthCredentials: llm.EnvSecretVar("env.UNSET_VERTEX_AUTH_CREDS", ""),
				Region:          schemas.SecretVar{Val: "us-central1"},
				ProjectNumber:   schemas.SecretVar{Val: "12345"},
			},
		}},
	}
	err := llm.ValidateEnvVars(&entry)
	if !errors.Is(err, llm.ErrEnvVarUnset) {
		t.Errorf("got %v, want ErrEnvVarUnset", err)
	}
}

func TestValidateEnvVars_PointerEnvVarUnset(t *testing.T) {
	t.Parallel()

	clientID := llm.EnvSecretVar("env.UNSET_AZ_CLIENT_ID", "")
	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "azure",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "az",
			Value:  schemas.SecretVar{Val: "literal"},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
			AzureKeyConfig: &schemas.AzureKeyConfig{ //nolint:exhaustruct // only Endpoint and ClientID populated
				Endpoint: schemas.SecretVar{Val: "https://example.com"},
				ClientID: &clientID,
			},
		}},
	}
	err := llm.ValidateEnvVars(&entry)
	if !errors.Is(err, llm.ErrEnvVarUnset) {
		t.Errorf("got %v, want ErrEnvVarUnset", err)
	}
}

func TestValidateEnvVars_PointerEnvVarNil(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "azure",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "az",
			Value:  schemas.SecretVar{Val: "literal"},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
			AzureKeyConfig: &schemas.AzureKeyConfig{ //nolint:exhaustruct // ClientID nil is the test case
				Endpoint: schemas.SecretVar{Val: "https://example.com"},
			},
		}},
	}
	if err := llm.ValidateEnvVars(&entry); err != nil {
		t.Errorf("nil ClientID pointer should not error: %v", err)
	}
}

func TestValidateEnvVars_LiteralEmptyDoesNotError(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "openai",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "k",
			Value:  schemas.SecretVar{Val: ""},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
		}},
	}
	if err := llm.ValidateEnvVars(&entry); err != nil {
		t.Errorf("literal empty should not error: %v", err)
	}
}

func TestValidateEnvVars_EmptyEntry(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{} //nolint:exhaustruct // empty entry is the test case
	if err := llm.ValidateEnvVars(&entry); err != nil {
		t.Errorf("empty provider entry should not error: %v", err)
	}
}

func TestValidateEnvVars_NilEntry(t *testing.T) {
	t.Parallel()

	if err := llm.ValidateEnvVars(nil); err != nil {
		t.Errorf("nil entry should not error: %v", err)
	}
}
