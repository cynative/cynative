#!/bin/sh
# e2e-guardrails.unit.test.sh - offline unit tests for the shared live-e2e
# guardrails library (test/lib/e2e-guardrails.sh, cynative#51).
#
# Hermetic: no network, no credentials, no cynative build. It sources the library
# and exercises the pure helpers - the bound exports, the tmp-dir isolation, the
# bounded-run exit-code propagation, and the run classifier (including the
# budget-hit case that must not read as a bogus "answer missing"). Run by
# `make sh-test` alongside the install.sh unit tests.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck source=test/lib/e2e-guardrails.sh
. "$here/lib/e2e-guardrails.sh"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

# ---- e2e_apply_bounds: defaults ------------------------------------------------
if (
	e2e_apply_bounds
	[ "$CYNATIVE_MAX_TOTAL_TOKENS" = "16000" ] || exit 1
	[ "$CYNATIVE_MAX_ITERATIONS" = "16" ] || exit 1
	[ "$CYNATIVE_MAX_SUBAGENT_ITERATIONS" = "3" ] || exit 1
	[ "$CYNATIVE_SANDBOX_MAX_CONCURRENCY" = "4" ] || exit 1
	[ "$CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS" = "60" ] || exit 1
); then pass "apply_bounds exports defaults"; else fail "apply_bounds defaults"; fi

# ---- e2e_apply_bounds: overrides -----------------------------------------------
if (
	E2E_MAX_TOKENS=32000
	E2E_MAX_ITERATIONS=1
	E2E_SUBAGENT_ITERATIONS=2
	E2E_SANDBOX_CONCURRENCY=8
	E2E_REQUEST_TIMEOUT=45
	e2e_apply_bounds
	[ "$CYNATIVE_MAX_TOTAL_TOKENS" = "32000" ] || exit 1
	[ "$CYNATIVE_MAX_ITERATIONS" = "1" ] || exit 1
	[ "$CYNATIVE_MAX_SUBAGENT_ITERATIONS" = "2" ] || exit 1
	[ "$CYNATIVE_SANDBOX_MAX_CONCURRENCY" = "8" ] || exit 1
	[ "$CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS" = "45" ] || exit 1
); then pass "apply_bounds honors E2E_* overrides"; else fail "apply_bounds overrides"; fi

# ---- e2e_apply_bounds: per-request timeout defaults to the run wall-clock ------
if (
	# With no explicit E2E_REQUEST_TIMEOUT, the per-LLM-call timeout follows
	# E2E_RUN_TIMEOUT, so it never fires before the run itself would.
	E2E_RUN_TIMEOUT=120
	e2e_apply_bounds
	[ "$CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS" = "120" ] || exit 1
	# An explicit request timeout still wins over the run wall-clock.
	E2E_REQUEST_TIMEOUT=30
	e2e_apply_bounds
	[ "$CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS" = "30" ] || exit 1
); then pass "apply_bounds derives request timeout from run wall-clock, explicit wins"; else fail "apply_bounds request-timeout derivation"; fi

# ---- e2e_isolate_env -----------------------------------------------------------
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	GITHUB_TOKEN=secret GH_TOKEN=secret GITLAB_TOKEN=secret GITLAB_ACCESS_TOKEN=secret OAUTH_TOKEN=secret
	KUBECONFIG=/tmp/kube GH_CONFIG_DIR=/tmp/gh GLAB_CONFIG_DIR=/tmp/glab
	export GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN GITLAB_ACCESS_TOKEN OAUTH_TOKEN
	export KUBECONFIG GH_CONFIG_DIR GLAB_CONFIG_DIR
	e2e_isolate_env "$td"
	[ -f "$td/config.yaml" ] || exit 1     # config written
	[ ! -s "$td/config.yaml" ] || exit 1   # and empty (ignores caller's config)
	[ "$CYNATIVE_CACHE_DIR" = "$td/cache" ] || exit 1
	# Token vars are cleared outright.
	[ -z "${GITHUB_TOKEN:-}" ] || exit 1
	[ -z "${GH_TOKEN:-}" ] || exit 1
	[ -z "${GITLAB_TOKEN:-}" ] || exit 1
	[ -z "${GITLAB_ACCESS_TOKEN:-}" ] || exit 1
	[ -z "${OAUTH_TOKEN:-}" ] || exit 1
	# The config-dir vars are NEUTRALIZED, not unset: unsetting them sends gh, glab,
	# and kubectl back to their DEFAULT locations (~/.config/gh, ~/.kube/config),
	# which is the opposite of isolation on a maintainer's machine.
	[ "$GH_CONFIG_DIR" = "$td/empty-gh" ] || exit 1
	[ -d "$GH_CONFIG_DIR" ] || exit 1
	[ "$GLAB_CONFIG_DIR" = "$td/empty-glab" ] || exit 1
	[ -d "$GLAB_CONFIG_DIR" ] || exit 1
	[ "$KUBECONFIG" = "$td/empty-kubeconfig" ] || exit 1
	[ -f "$KUBECONFIG" ] || exit 1
	[ ! -s "$KUBECONFIG" ] || exit 1
); then pass "isolate_env writes empty config, sets cache, clears tokens, neutralizes config dirs"; else fail "isolate_env"; fi

# ---- e2e_build_binary: prebuilt path -------------------------------------------
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	# A non-executable prebuilt is rejected.
	: > "$td/notexec"
	if e2e_build_binary "$td/root" "$td" "$td/notexec" >/dev/null 2>&1; then exit 1; fi
	# An executable prebuilt is echoed back verbatim (no build).
	printf '#!/bin/sh\n' > "$td/exec"
	chmod +x "$td/exec"
	out=$(e2e_build_binary "$td/root" "$td" "$td/exec") || exit 1
	[ "$out" = "$td/exec" ] || exit 1
	# With no prebuilt and go unavailable, the build path fails closed (clear msg).
	if ( PATH='' e2e_build_binary "$td/root" "$td" >/dev/null 2>&1 ); then exit 1; fi
); then pass "build_binary accepts an executable prebuilt, rejects non-executable, needs go to build"; else fail "build_binary prebuilt"; fi

# ---- e2e_run_bounded: exit-code propagation + stream capture -------------------
# Needs `timeout` (the wrapper invokes it); skip cleanly if absent.
if command -v timeout >/dev/null 2>&1; then
	if (
		td=$(mktemp -d)
		trap 'rm -rf "$td"' EXIT
		runrc() {  # rc of a bounded run against stub "$1"
			if e2e_run_bounded 3 "$td/audit" "$td/o" "$td/e" "$1" "$td/cfg" "prompt"; then
				echo 0
			else
				echo $?
			fi
		}
		# A non-zero exit must propagate (guards the `return $?` fall-through bug).
		printf '#!/bin/sh\necho OUT\necho ERR >&2\nexit 7\n' > "$td/exit7"
		chmod +x "$td/exit7"
		[ "$(runrc "$td/exit7")" -eq 7 ] || exit 1
		grep -Fq OUT "$td/o" || exit 1   # stdout captured
		grep -Fq ERR "$td/e" || exit 1   # stderr captured
		# A clean exit is 0.
		printf '#!/bin/sh\nexit 0\n' > "$td/exit0"
		chmod +x "$td/exit0"
		[ "$(runrc "$td/exit0")" -eq 0 ] || exit 1
		# Overrunning the wall-clock yields 124.
		printf '#!/bin/sh\nsleep 5\n' > "$td/slow"
		chmod +x "$td/slow"
		if e2e_run_bounded 1 "$td/audit" "$td/o" "$td/e" "$td/slow" "$td/cfg" "prompt"; then
			trc=0
		else
			trc=$?
		fi
		[ "$trc" -eq 124 ] || exit 1
		# Extra trailing args (e.g. --verbose) are passed through to the binary.
		printf '#!/bin/sh\nprintf "%%s\\n" "$*"\n' > "$td/echoargs"
		chmod +x "$td/echoargs"
		if e2e_run_bounded 3 "$td/audit" "$td/o3" "$td/e3" "$td/echoargs" "$td/cfg" "prompt" --verbose --foo; then :; fi
		grep -Fq -- '--verbose --foo' "$td/o3" || exit 1
	); then pass "run_bounded propagates exit 7/0, captures streams, times out to 124, passes extra args"; else fail "run_bounded"; fi
else
	printf 'skip: run_bounded case (timeout not found)\n' >&2
fi

# ---- e2e_classify_run: four cases ----------------------------------------------
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	printf 'answer text\n' > "$td/ok.out"
	: > "$td/empty.err"
	printf 'boom\n' > "$td/boom.err"
	# The agent writes the budget notice to STDOUT and exits 0 on a budget hit;
	# only the ASCII "Budget reached" substring is load-bearing.
	printf 'Budget reached - token budget reached: 100 / 50 tokens. Stopping;\n' > "$td/budget.out"

	# Capture classify_run's rc without tripping set -e on its intentional
	# non-zero returns (the house if/else pattern).
	classrc() {
		if e2e_classify_run "$1" "$2" "$3" "$4" >/dev/null 2>&1; then echo 0; else echo $?; fi
	}

	[ "$(classrc 0   "$td/ok.out"     "$td/empty.err" 60)" -eq 0 ] || exit 1  # ok
	[ "$(classrc 124 "$td/ok.out"     "$td/empty.err" 60)" -eq 2 ] || exit 1  # timeout
	[ "$(classrc 0   "$td/budget.out" "$td/empty.err" 60)" -eq 3 ] || exit 1  # budget (rc 0!)
	[ "$(classrc 1   "$td/ok.out"     "$td/boom.err"  60)" -eq 1 ] || exit 1  # generic
	[ "$(classrc 124 "$td/budget.out" "$td/empty.err" 60)" -eq 2 ] || exit 1  # timeout dominates
); then pass "classify_run maps ok/timeout/budget/failure to 0/2/3/1"; else fail "classify_run"; fi

# ---- e2e_require_cmd -----------------------------------------------------------
if (
	e2e_require_cmd sh >/dev/null 2>&1 || exit 1                 # present
	if e2e_require_cmd definitely-not-a-real-cmd-xyz >/dev/null 2>&1; then exit 1; fi  # absent
); then pass "require_cmd passes for present, fails for absent"; else fail "require_cmd"; fi

# ---- e2e_require_env -----------------------------------------------------------
if (
	E2E_UNIT_SET='present'
	export E2E_UNIT_SET
	unset E2E_UNIT_MISSING 2>/dev/null || true
	# Every var present: proceed.
	e2e_require_env demo "" E2E_UNIT_SET >/dev/null 2>&1 || exit 1
	# A missing var with REQUIRE_RUN unset signals "skip" (rc 1) without exiting, so
	# the caller's `|| exit 0` turns it into a clean skip.
	if e2e_require_env demo "" E2E_UNIT_SET E2E_UNIT_MISSING >/dev/null 2>&1; then exit 1; fi
	# With REQUIRE_RUN=1 it must EXIT the script, not return: a `return 1` would be
	# swallowed by the caller's `|| exit 0` and a CI job would go green by skipping.
	# Prove it by running the real caller expression in a subshell: if the helper
	# only returned, the `|| exit 0` would make this subshell exit 0.
	if ( e2e_require_env demo 1 E2E_UNIT_SET E2E_UNIT_MISSING >/dev/null 2>&1 || exit 0 ); then exit 1; fi
); then pass "require_env proceeds, signals skip, and hard-EXITS under REQUIRE_RUN=1"; else fail "require_env"; fi

# ---- e2e_run_with_retries ------------------------------------------------------
# The phase callbacks are defined at top level (not inside the `if (...)` subshell)
# because they are invoked indirectly, by name, and ShellCheck only resolves that
# reference at top level (SC2329).
retry_dir=$(mktemp -d)
trap 'rm -rf "$retry_dir"' EXIT

# Fails once, then succeeds: must be retried and pass.
unit_flaky() {
	printf 'x' >> "$retry_dir/flaky"
	[ "$(wc -c < "$retry_dir/flaky")" -ge 2 ]
}
# Budget hit: fatal, must be invoked exactly once.
unit_budget() { printf 'x' >> "$retry_dir/budget"; return 3; }
# Security failure: fatal, must be invoked exactly once. Retrying would erase the
# evidence (the audit log is truncated per attempt) and let a broken gate pass.
unit_security() { printf 'x' >> "$retry_dir/security"; return 4; }
# Always fails: must exhaust the attempts.
unit_always() { printf 'x' >> "$retry_dir/always"; return 1; }

if (
	: > "$retry_dir/flaky"
	e2e_run_with_retries flaky 2 unit_flaky >/dev/null 2>&1 || exit 1
	[ "$(wc -c < "$retry_dir/flaky")" -eq 2 ] || exit 1

	: > "$retry_dir/budget"
	if ( e2e_run_with_retries budget 3 unit_budget >/dev/null 2>&1 ); then exit 1; fi
	[ "$(wc -c < "$retry_dir/budget")" -eq 1 ] || exit 1

	: > "$retry_dir/security"
	if ( e2e_run_with_retries security 3 unit_security >/dev/null 2>&1 ); then exit 1; fi
	[ "$(wc -c < "$retry_dir/security")" -eq 1 ] || exit 1

	: > "$retry_dir/always"
	if ( e2e_run_with_retries always 2 unit_always >/dev/null 2>&1 ); then exit 1; fi
	[ "$(wc -c < "$retry_dir/always")" -eq 2 ] || exit 1

	# An out-of-range attempt count is rejected rather than silently clamped.
	if ( e2e_run_with_retries bad 9 unit_always >/dev/null 2>&1 ); then exit 1; fi
); then pass "run_with_retries retries a miss, never retries a budget (3) or security (4) failure"; else fail "run_with_retries"; fi

# ---- e2e_assert_tool_called ----------------------------------------------------
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	printf 'footer: 3 tool calls\n' > "$td/some.err"
	printf 'footer: 1 tool call\n' > "$td/one.err"
	printf 'footer: 0 tool calls\n' > "$td/zero.err"
	: > "$td/none.err"
	e2e_assert_tool_called "$td/some.err" >/dev/null 2>&1 || exit 1
	e2e_assert_tool_called "$td/one.err" >/dev/null 2>&1 || exit 1
	if e2e_assert_tool_called "$td/zero.err" >/dev/null 2>&1; then exit 1; fi
	# A MISSING footer must fail. The old "reject 0 tool calls" check passed here,
	# so a run that produced no footer at all looked like a success.
	if e2e_assert_tool_called "$td/none.err" >/dev/null 2>&1; then exit 1; fi
); then pass "assert_tool_called requires a positive count, fails on 0 and on a missing footer"; else fail "assert_tool_called"; fi

# ---- e2e_run_bounded truncates the audit log before each attempt ---------------
if command -v timeout >/dev/null 2>&1; then
	if (
		td=$(mktemp -d)
		trap 'rm -rf "$td"' EXIT
		printf '{"stale":"record"}\n' > "$td/audit"
		printf '#!/bin/sh\nexit 0\n' > "$td/noop"
		chmod +x "$td/noop"
		e2e_run_bounded 3 "$td/audit" "$td/o" "$td/e" "$td/noop" "$td/cfg" "prompt" || exit 1
		# The audit log is append-only, so without truncation a retried phase could be
		# judged against a previous attempt's records.
		[ ! -s "$td/audit" ] || exit 1
	); then pass "run_bounded truncates the audit log so a retry sees only its own records"; else fail "run_bounded audit truncation"; fi
fi

if [ "$fails" -ne 0 ]; then
	printf 'e2e-guardrails.unit: %d case(s) FAILED\n' "$fails" >&2
	exit 1
fi
printf 'e2e-guardrails.unit: OK\n' >&2
