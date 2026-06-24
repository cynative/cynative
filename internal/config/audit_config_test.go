package config_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cynative/cynative/internal/config"
)

func TestLoad_AuditDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER": "openai",
		"CYNATIVE_LLM_MODEL":    "gpt-5",
		"OPENAI_API_KEY":        "sk-x",
	}).Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Audit.Enabled {
		t.Error("Audit.Enabled default should be true")
	}
	if cfg.Audit.MaxSizeMB != 100 {
		t.Errorf("MaxSizeMB: got %d want 100", cfg.Audit.MaxSizeMB)
	}
	if cfg.Audit.RetentionDays != 30 {
		t.Errorf("RetentionDays: got %d want 30", cfg.Audit.RetentionDays)
	}
	if cfg.Audit.Compress {
		t.Error("Compress default should be false")
	}
}

func TestLoad_AuditEnvOverrideAndTilde(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	l := config.NewLoader(envMap(map[string]string{
		"CYNATIVE_LLM_PROVIDER":         "openai",
		"CYNATIVE_LLM_MODEL":            "gpt-5",
		"OPENAI_API_KEY":                "sk-x",
		"CYNATIVE_AUDIT_ENABLED":        "false",
		"CYNATIVE_AUDIT_PATH":           "~/logs/audit.log",
		"CYNATIVE_AUDIT_MAX_SIZE_MB":    "5",
		"CYNATIVE_AUDIT_RETENTION_DAYS": "7",
		"CYNATIVE_AUDIT_COMPRESS":       "true",
	}), config.WithHomeDir(func() (string, error) { return home, nil }))

	cfg, err := l.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.Enabled {
		t.Error("Enabled should be false from env")
	}
	if cfg.Audit.Path != filepath.Join(home, "logs", "audit.log") {
		t.Errorf("Path tilde not expanded: %q", cfg.Audit.Path)
	}
	if cfg.Audit.MaxSizeMB != 5 || cfg.Audit.RetentionDays != 7 || !cfg.Audit.Compress {
		t.Errorf("env overrides not applied: %+v", cfg.Audit)
	}
}

func TestLoad_AuditPathTilde_HomeError(t *testing.T) {
	t.Parallel()

	// Use an explicit config file so Load skips the first homeDir call for
	// config-path resolution. cache.dir is set to an absolute path so its
	// expandTilde is a no-op; the home-dir error must surface from the
	// audit.path tilde expansion specifically.
	cfgPath := writeConfig(t, `
llm:
  provider: openai
  model: gpt-5
  keys:
    - name: k
      value: literal-key
      models: ["*"]
      weight: 1.0
cache:
  dir: /tmp/cache
audit:
  path: ~/audit.log
`)
	homeErr := errors.New("home dir unavailable")
	l := config.NewLoader(
		envMap(nil),
		config.WithHomeDir(func() (string, error) { return "", homeErr }),
	)

	if _, err := l.Load(cfgPath); err == nil {
		t.Fatal("expected error when home-dir resolution fails for audit.path")
	}
}

func TestLoad_AuditValidation_RejectsZeroSize(t *testing.T) {
	t.Parallel()

	_, err := loaderEnv(t, map[string]string{
		"CYNATIVE_LLM_PROVIDER":      "openai",
		"CYNATIVE_LLM_MODEL":         "gpt-5",
		"OPENAI_API_KEY":             "sk-x",
		"CYNATIVE_AUDIT_MAX_SIZE_MB": "0",
	}).Load("")
	if err == nil {
		t.Fatal("expected validation error for max_size_mb=0")
	}
}
