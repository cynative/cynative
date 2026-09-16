package config_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/config"
)

// TestLoad_GCPCredentialsFile pins connectors.gcp.credentials_file: unset by
// default (ADC), bound from its env var, and tilde-expanded like cache.dir.
func TestLoad_GCPCredentialsFile(t *testing.T) {
	t.Parallel()

	t.Run("default is empty (ADC)", func(t *testing.T) {
		t.Parallel()
		cfg, err := loaderEnv(t, baseLLMEnv()).Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Connectors.GCP.CredentialsFile != "" {
			t.Errorf("credentials_file default = %q, want empty", cfg.Connectors.GCP.CredentialsFile)
		}
	})

	t.Run("tilde expands against the loader home", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		env := baseLLMEnv()
		env["CYNATIVE_CONNECTORS_GCP_CREDENTIALS_FILE"] = "~/keys/bench.json"
		l := config.NewLoader(envMap(env), config.WithHomeDir(func() (string, error) { return home, nil }))
		cfg, err := l.Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if want := filepath.Join(home, "keys", "bench.json"); cfg.Connectors.GCP.CredentialsFile != want {
			t.Errorf("credentials_file = %q, want %q", cfg.Connectors.GCP.CredentialsFile, want)
		}
	})

	t.Run("home error surfaces from the credentials_file expansion", func(t *testing.T) {
		t.Parallel()
		// An explicit config file skips the home lookup for the default config
		// path, and cache.dir / audit.path are absolute so their expansions are
		// no-ops; the only tilde left is the one under test.
		cfgPath := writeConfig(t, `
llm:
  provider: openai
  model: gpt-5
  api_key: literal-key
cache:
  dir: /tmp/cache
audit:
  path: /tmp/audit.log
connectors:
  gcp:
    credentials_file: ~/keys/bench.json
`)
		homeErr := errors.New("home dir unavailable")
		l := config.NewLoader(envMap(nil), config.WithHomeDir(func() (string, error) { return "", homeErr }))
		_, err := l.Load(cfgPath)
		if err == nil || !errors.Is(err, homeErr) || !strings.Contains(err.Error(), "connectors.gcp.credentials_file") {
			t.Fatalf("Load err = %v, want the home error attributed to connectors.gcp.credentials_file", err)
		}
	})
}
