package sandbox

import (
	"fmt"

	"github.com/grafana/sobek"
)

// buildRuntime creates the sobek runtime on s, registers the console object
// plus one JS function per entry in funcs, and evaluates the mapConcurrent
// prelude (its default limit is the semaphore capacity). It lives in the imperative shell
// (_shell.go) because it is exercised only through integration tests — every
// Run drives a real runtime — so its registration-error branches need no unit
// coverage and are excluded from the gate. It returns (rather than panics on)
// the registration error so this shell pattern stays uniform with adapters
// whose errors are reachable; in practice vm.Set only fails for nil values or
// invalid JS identifiers, neither of which this produces, so the error is never
// actually returned.
func buildRuntime(s *Sandbox, funcs map[string]ToolFunc) error {
	s.vm = sobek.New()

	statics := map[string]any{
		"console":  map[string]any{"log": s.consoleLog, "error": s.consoleLog},
		"xml":      map[string]any{"parse": s.xmlParse},
		"jmespath": map[string]any{"search": s.jmespathSearch},
	}
	if err := registerAll(s.vm.Set, statics); err != nil {
		return err
	}

	if _, err := s.vm.RunString(fmt.Sprintf(preludeJS, cap(s.sem))); err != nil {
		return fmt.Errorf("sandbox: install prelude: %w", err)
	}

	tools := make(map[string]any, len(funcs))
	for name, fn := range funcs {
		tools[name] = s.toolFunc(name, fn)
	}

	return registerAll(s.vm.Set, tools)
}
