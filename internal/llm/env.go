package llm

import (
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// LookupEnv resolves an environment variable, returning its value and whether
// it was set. It mirrors [os.LookupEnv] so the composition root can pass that
// function directly, while tests pass a map-backed lookup — keeping config
// loading hermetic and parallel-safe (no t.Setenv).
type LookupEnv func(string) (string, bool)

// ResolveEnvVar turns a config string into a schemas.SecretVar, resolving an
// "env.NAME" reference through env instead of the process environment (as
// schemas.NewSecretVar would). A reference yields an env-typed SecretVar whose
// value comes from env, with the "env.NAME" reference preserved so an unset
// reference leaves the value empty for ValidateEnvVars to surface at startup. A
// plain string is a literal (plain-text) value.
func ResolveEnvVar(s string, env LookupEnv) schemas.SecretVar {
	if name, ok := strings.CutPrefix(s, "env."); ok {
		val, _ := env(name)

		return EnvSecretVar(s, val)
	}

	return schemas.SecretVar{Val: s}
}

// EnvSecretVar builds an env-typed schemas.SecretVar that records the "env.NAME"
// reference (so ValidateEnvVars can detect and name an unset variable) while
// carrying resolvedValue obtained through cynative's injected LookupEnv. Because
// SecretVar's reference field is unexported, schemas.NewSecretVar is the only way
// to set it; its process-environment read is immediately overwritten by
// resolvedValue, so the injected env stays authoritative (ref must be the full
// "env.NAME" form).
func EnvSecretVar(ref, resolvedValue string) schemas.SecretVar {
	sv := schemas.NewSecretVar(ref)
	sv.Val = resolvedValue

	return *sv
}
