package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/grafana/sobek"
)

// sanitizedError carries a redacted message surfaced to the script (as a thrown
// JS error) and to the verbose log. Using a named type instead of [errors.New]
// keeps the redacted message off the linter's dynamic-error radar.
type sanitizedError struct{ msg string }

func (e sanitizedError) Error() string { return e.msg }

// wrapPrefix/wrapSuffix wrap a script in an async IIFE so top-level await is
// legal and top-level declarations are call-scoped. No newline after the
// prefix keeps line numbers aligned for lines 2+.
const (
	wrapPrefix = "(async () => {"
	wrapSuffix = "\n})()"
)

// compileWrapped compiles the user's code wrapped in an async IIFE. Invalid
// JavaScript (e.g. syntax errors) produces a non-nil error that Run surfaces as
// a script error in the result string.
func compileWrapped(code string) (*sobek.Program, error) {
	return sobek.Compile("<code_execution>", wrapPrefix+code+wrapSuffix, false)
}

// loop applies worker postbacks until no inner tool call is in flight. Each
// postback runs on this (the loop) goroutine and calls resolve/reject, which
// drains the microtask queue (running await/.then continuations that may issue
// further tool calls). It returns a non-nil error only for uncatchable VM
// errors (e.g. an interrupt raised mid-drain).
func (s *Sandbox) loop() error {
	for s.inFlight > 0 {
		select {
		case <-s.runCtx.Done():
			return nil // Timeout/cancel; assemble reports it from runCtx.Err().
		case pb := <-s.pending:
			if err := pb(); err != nil {
				return err
			}
		}
	}

	return nil
}

// toolFunc adapts a ToolFunc into an async sobek function returning a Promise.
// It runs on the loop goroutine: it creates the promise, increments the
// in-flight count, and spawns a worker; it never blocks.
func (s *Sandbox) toolFunc(name string, fn ToolFunc) func(sobek.FunctionCall) sobek.Value {
	return func(call sobek.FunctionCall) sobek.Value {
		argsJSON := marshalArg(call.Argument(0))

		if s.verbose != nil {
			fmt.Fprintf(s.verbose, "\u2192 %s %s\n", name, clip(argsJSON))
		}

		promise, resolve, reject := s.vm.NewPromise()
		s.inFlight++

		s.workers.Go(func() {
			s.runWorker(s.runCtx, name, fn, argsJSON, resolve, reject)
		})

		return s.vm.ToValue(promise)
	}
}

// runWorker runs the blocking ToolFunc off the loop goroutine, then posts a
// closure back to the loop to settle the promise. resolve/reject are only ever
// called from inside that closure (i.e. on the loop goroutine).
func (s *Sandbox) runWorker(
	ctx context.Context,
	name string,
	fn ToolFunc,
	argsJSON string,
	resolve, reject func(any) error,
) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-s.done:
		return
	}

	result, err := fn(ctx, argsJSON)

	// Layer 1 (sandbox-ingress): redact at the source — before the verbose log,
	// before toJSResult/resolve, and before reject — so a raw secret never
	// reaches model-authored JS, the verbose writer, or (via transform) the model.
	result = s.redact(result)
	if err != nil {
		err = sanitizedError{msg: s.redact(err.Error())}
	}

	settle := func() error {
		s.inFlight--

		if s.verbose != nil {
			if err != nil {
				fmt.Fprintf(s.verbose, "\u2190 %s error: %v\n", name, err)
			} else {
				fmt.Fprintf(s.verbose, "\u2190 %s %s\n", name, clip(result))
			}
		}

		if err != nil {
			return reject(s.vm.NewGoError(err))
		}

		return resolve(toJSResult(s.vm, result))
	}

	select {
	case s.pending <- settle:
	case <-s.done:
	}
}

// toJSResult resolves a tool's string result to a JS value: if it looks like a
// JSON object or array and parses, it becomes a JS object/array; otherwise it
// stays a string. This is what gives http_request's structured JSON a JS-object
// shape inside the sandbox.
func toJSResult(vm *sobek.Runtime, result string) any {
	trimmed := strings.TrimLeft(result, " \t\r\n")
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var parsed any
		if json.Unmarshal([]byte(result), &parsed) == nil {
			return vm.ToValue(parsed)
		}
	}

	return result
}
