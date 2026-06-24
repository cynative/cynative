package llm_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/cynative/cynative/internal/llm"
)

// Compile-time pin: ValidateEnvVars reads three specific field names on
// schemas.EnvVar (Val, FromEnv, EnvVar). If Bifrost renames any of them in
// a future version, this declaration fails the build instead of silently
// regressing env-var validation at runtime.
var _ = schemas.EnvVar{
	Val:     "",
	FromEnv: false,
	EnvVar:  "",
}

func TestValidateEnvVars_NoEnvVars(t *testing.T) {
	t.Parallel()

	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "openai",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "k",
			Value:  schemas.EnvVar{Val: "literal", FromEnv: false, EnvVar: ""},
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
			Value:  schemas.EnvVar{Val: "resolved", FromEnv: true, EnvVar: "env.OPENAI_KEY"},
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
			Value:  schemas.EnvVar{Val: "", FromEnv: true, EnvVar: "env.UNSET_OPENAI"},
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
			Value:  schemas.EnvVar{Val: "literal", FromEnv: false, EnvVar: ""},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
			VertexKeyConfig: &schemas.VertexKeyConfig{
				ProjectID:       schemas.EnvVar{Val: "p", FromEnv: false, EnvVar: ""},
				AuthCredentials: schemas.EnvVar{Val: "", FromEnv: true, EnvVar: "env.UNSET_VERTEX_AUTH_CREDS"},
				Region:          schemas.EnvVar{Val: "us-central1", FromEnv: false, EnvVar: ""},
				ProjectNumber:   schemas.EnvVar{Val: "12345", FromEnv: false, EnvVar: ""},
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

	clientID := schemas.EnvVar{Val: "", FromEnv: true, EnvVar: "env.UNSET_AZ_CLIENT_ID"}
	entry := llm.ProviderEntry{ //nolint:exhaustruct // only Provider+Keys populated
		Provider: "azure",
		Keys: []schemas.Key{{ //nolint:exhaustruct // only required fields populated
			Name:   "az",
			Value:  schemas.EnvVar{Val: "literal", FromEnv: false, EnvVar: ""},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
			AzureKeyConfig: &schemas.AzureKeyConfig{ //nolint:exhaustruct // only Endpoint and ClientID populated
				Endpoint: schemas.EnvVar{Val: "https://example.com", FromEnv: false, EnvVar: ""},
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
			Value:  schemas.EnvVar{Val: "literal", FromEnv: false, EnvVar: ""},
			Models: schemas.WhiteList{"*"},
			Weight: 1,
			AzureKeyConfig: &schemas.AzureKeyConfig{ //nolint:exhaustruct // ClientID nil is the test case
				Endpoint: schemas.EnvVar{Val: "https://example.com", FromEnv: false, EnvVar: ""},
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
			Value:  schemas.EnvVar{Val: "", FromEnv: false, EnvVar: ""},
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
