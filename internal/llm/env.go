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

// ResolveEnvVar turns a config string into a schemas.EnvVar, resolving an
// "env.NAME" reference through env instead of the process environment (as
// schemas.NewEnvVar would). A reference always yields FromEnv=true with the
// original "env.NAME" preserved in EnvVar; an unset reference leaves Val empty
// so ValidateEnvVars surfaces it at startup. A plain string is a literal value.
func ResolveEnvVar(s string, env LookupEnv) schemas.EnvVar {
	if name, ok := strings.CutPrefix(s, "env."); ok {
		val, _ := env(name)

		return schemas.EnvVar{Val: val, FromEnv: true, EnvVar: s}
	}

	return schemas.EnvVar{Val: s, FromEnv: false, EnvVar: ""}
}
