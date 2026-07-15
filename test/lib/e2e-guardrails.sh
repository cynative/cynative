# shellcheck shell=sh
# e2e-guardrails.sh - shared cost/timeout guardrails for the live e2e suites
# (cynative#51). Sourced, never executed: it defines helpers and has no side
# effects at source time, so an offline caller (e.g. the connector script's
# --selftest) can source it safely.
#
# It keeps the live suites - the LLM smoke and the gcp/aws/github connector e2es -
# on one bounded configuration so a broken live run cannot quietly burn credits,
# hang a runner, or leave a maintainer guessing.
#
# The library reads no suite-specific env. Callers resolve their own public knobs
# (SMOKE_* / GCP_E2E_*) into the generic E2E_* override vars before calling
# e2e_apply_bounds, so the library stays generic and the documented per-suite
# knobs keep working.
#
# Guardrail defaults (override by setting the E2E_* var before e2e_apply_bounds):
#   E2E_MAX_TOKENS          16000  -> CYNATIVE_MAX_TOTAL_TOKENS (token ceiling)
#   E2E_MAX_ITERATIONS      16     -> CYNATIVE_MAX_ITERATIONS (main loop cap; the
#                                     no-tool llm smoke overrides down to 1)
#   E2E_SUBAGENT_ITERATIONS 3      -> CYNATIVE_MAX_SUBAGENT_ITERATIONS
#   E2E_SANDBOX_CONCURRENCY 4      -> CYNATIVE_SANDBOX_MAX_CONCURRENCY
#   E2E_REQUEST_TIMEOUT     =E2E_RUN_TIMEOUT (per-LLM-call timeout) ->
#                                  CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS
#   E2E_RUN_TIMEOUT         60     -> the shell `timeout` wall-clock per run. Not a
#                                     cynative knob (passed to e2e_run_bounded);
#                                     also the default basis for E2E_REQUEST_TIMEOUT.
# There is no separate whole-script watchdog: the effective ceiling is the
# per-run timeout times the capped attempts and phases, and a budget hit is
# fatal (never retried). Each suite documents its derived worst case.

# e2e_require_cmd CMD [HINT] - fail closed if CMD is not on PATH.
e2e_require_cmd() {
	command -v "$1" >/dev/null 2>&1 && return 0
	printf 'FAIL: %s not found%s\n' "$1" "${2:+ ($2)}" >&2
	return 1
}

# e2e_apply_bounds - export the guardrail env from the E2E_* overrides (with the
# documented defaults). Must run in the current shell (it exports), so do NOT
# call it via command substitution. Idempotent.
e2e_apply_bounds() {
	export CYNATIVE_MAX_TOTAL_TOKENS="${E2E_MAX_TOKENS:-16000}"
	export CYNATIVE_MAX_ITERATIONS="${E2E_MAX_ITERATIONS:-16}"
	export CYNATIVE_MAX_SUBAGENT_ITERATIONS="${E2E_SUBAGENT_ITERATIONS:-3}"
	export CYNATIVE_SANDBOX_MAX_CONCURRENCY="${E2E_SANDBOX_CONCURRENCY:-4}"
	# Per-LLM-call timeout defaults to the per-run wall-clock, so it never fires
	# before the run itself would - avoiding a spurious cut-off of a legitimately
	# slow reasoning turn (cynative's own default is 300s for exactly this reason).
	# Raising the wall-clock knob (SMOKE_TIMEOUT / GCP_E2E_TIMEOUT) raises this too;
	# a caller can still pin it explicitly via E2E_REQUEST_TIMEOUT.
	export CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS="${E2E_REQUEST_TIMEOUT:-${E2E_RUN_TIMEOUT:-60}}"
}

# e2e_isolate_env WORKDIR - isolate cynative's config/cache from the caller and
# silence connector-discovery env unrelated to any LLM provider. Writes an empty
# WORKDIR/config.yaml (so the caller's ~/.cynative/config.yaml is ignored) and
# points the cache at WORKDIR. It does NOT set CYNATIVE_AUDIT_PATH: a caller that
# runs multiple phases sets a per-phase audit path itself. Runs in the current
# shell (it exports/unsets); do not call via command substitution.
e2e_isolate_env() {
	: > "$1/config.yaml"
	export CYNATIVE_CACHE_DIR="$1/cache"
	# AWS/GCP/Azure creds are left alone: an LLM provider may need them (e.g.
	# Bedrock uses AWS creds). The suite's own tool-call / connector assertions
	# are the safety net for whether a connector should be dark.
	unset GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN GITLAB_ACCESS_TOKEN OAUTH_TOKEN
	# The config-dir vars are NEUTRALIZED, not unset. gh, glab, and kubectl all fall
	# back to a DEFAULT location when their env var is absent (~/.config/gh,
	# ~/.kube/config), so unsetting them hands a maintainer's real credentials to a
	# suite that meant to silence them. Empty paths make discovery find nothing.
	mkdir -p "$1/empty-gh" "$1/empty-glab"
	: > "$1/empty-kubeconfig"
	export GH_CONFIG_DIR="$1/empty-gh"
	export GLAB_CONFIG_DIR="$1/empty-glab"
	export KUBECONFIG="$1/empty-kubeconfig"
}

# e2e_build_binary ROOT WORKDIR [PREBUILT] - print a usable cynative binary path.
# With PREBUILT: validate it is executable and echo it. Without: build the
# current checkout (go build ./cmd/cynative from ROOT) into WORKDIR. Safe to call
# via command substitution (it only prints the path; no exports).
e2e_build_binary() {
	_root=$1
	_workdir=$2
	_prebuilt=${3:-}
	if [ -n "$_prebuilt" ]; then
		[ -x "$_prebuilt" ] || { printf 'FAIL: binary not executable: %s\n' "$_prebuilt" >&2; return 1; }
		printf '%s\n' "$_prebuilt"
		return 0
	fi
	_bin="$_workdir/cynative"
	e2e_require_cmd go "needed to build cynative" || return 1
	printf '== BUILD ==\n' >&2
	( cd "$_root" && go build -o "$_bin" ./cmd/cynative ) || { printf 'FAIL: go build failed\n' >&2; return 1; }
	printf '%s\n' "$_bin"
}

# e2e_run_bounded RUN_TIMEOUT AUDIT OUT ERR BIN CONFIG PROMPT [EXTRA...] - run one
# bounded one-shot `cynative -p`. Assumes e2e_apply_bounds already exported the
# cynative guardrail env; this adds the per-phase audit path and the wall-clock
# `timeout`. Any args after PROMPT are passed through to cynative (e.g. --verbose).
# Captures the exit code safely under set -e and returns it (124 == timeout).
e2e_run_bounded() {
	_to=$1
	_audit=$2
	_out=$3
	_err=$4
	_bin=$5
	_cfg=$6
	_prompt=$7
	shift 7
	# Truncate the audit log before every attempt. cynative opens it append-only, so
	# without this a stale record from a failed earlier attempt could satisfy this
	# attempt's parser. This lives here, not in the callers, because this helper
	# already owns the audit path and a caller that forgot it would fail silently.
	# Fail closed: `set -e` is suppressed for a function used as an `if` condition,
	# so a failed truncation must be checked explicitly or the run would be judged
	# against a previous attempt's records.
	if ! : > "$_audit"; then
		printf 'FAIL: could not truncate the audit log: %s\n' "$_audit" >&2
		return 1
	fi
	# The exit code is captured in the else branch: a completed `if` with no
	# matching branch yields status 0, so `return $?` after `fi` would swallow a
	# timeout/failure. In the else, $? still holds the condition's exit status.
	if CYNATIVE_AUDIT_PATH="$_audit" \
		timeout "$_to" "$_bin" --config "$_cfg" -p "$_prompt" --auto-approve "$@" \
		>"$_out" 2>"$_err" </dev/null; then
		return 0
	else
		return $?
	fi
}

# e2e_classify_run RC OUT ERR RUN_TIMEOUT - classify a bounded run and print a
# clear, distinct failure. Returns:
#   0  success (rc 0 and no budget notice on stdout) - run domain assertions.
#   2  timeout (rc 124).
#   3  budget hit: "Budget reached" appears on stdout. The agent writes this to
#      stdout and exits 0, so the answer never lands; without this branch a
#      budget hit reads as a bogus "answer missing". Callers treat 3 as fatal and
#      do NOT retry (a retry only burns more credits and re-hits the ceiling).
#   1  any other non-zero rc (provider / config / access).
# Order matters: timeout, then budget (exits 0), then the generic rc branch.
e2e_classify_run() {
	if [ "$1" -eq 124 ]; then
		printf 'FAIL: timed out after %ss\n' "$4" >&2
		return 2
	fi
	if grep -Fq 'Budget reached' "$2" 2>/dev/null; then
		printf 'FAIL: token budget reached - raise the token limit (E2E_MAX_TOKENS / SMOKE_MAX_TOKENS / GCP_E2E_MAX_TOKENS). Notice:\n' >&2
		grep -F 'Budget reached' "$2" >&2 || true
		return 3
	fi
	if [ "$1" -ne 0 ]; then
		printf 'FAIL: provider/config/access (exit %s). stderr tail:\n' "$1" >&2
		tail -n 20 "$3" >&2
		return 1
	fi
	return 0
}

# Phase status contract, shared by the connector suites and e2e_run_with_retries:
#   0  the phase's assertions hold.
#   1  not proven this attempt (a model miss, a fumbled call, a transient failure).
#      Retryable: model runs are non-deterministic.
#   2  the run timed out.
#   3  the token budget was hit. FATAL: a retry only burns more credits and re-hits
#      the same ceiling.
#   4  a SECURITY assertion failed: a request the read-only boundary should have
#      stopped was dispatched, or a write succeeded. FATAL, and never retried.
#
# Status 4 exists because retrying a security failure would launder it. The retry
# helper truncates the audit log before each attempt, so a first attempt that caught
# a real boundary violation would have its evidence erased, and a second attempt that
# happened to be denied would let the suite exit 0 on a broken gate.
E2E_STATUS_BUDGET=3
E2E_STATUS_SECURITY=4

# e2e_require_env SUITE REQUIRE_RUN VAR... - gate a suite on its required env.
# Returns 0 when every VAR is set. Returns 1 (the caller should skip, exit 0) when
# one is missing. EXITS 1 when REQUIRE_RUN is "1", so a CI job can never go green by
# silently skipping a renamed or dropped variable.
e2e_require_env() {
	_suite=$1
	_require=$2
	shift 2
	_missing=
	for _v in "$@"; do
		eval "_val=\${$_v:-}"
		[ -n "$_val" ] || _missing="$_missing $_v"
	done
	[ -n "$_missing" ] || return 0
	if [ "$_require" = "1" ]; then
		printf 'FAIL: required env unset but REQUIRE_RUN=1 (%s):%s\n' "$_suite" "$_missing" >&2
		exit 1
	fi
	printf 'skip: %s (unset:%s)\n' "$_suite" "$_missing" >&2
	return 1
}

# e2e_run_with_retries LABEL ATTEMPTS PHASE_FN - run a phase, retrying a
# non-deterministic model miss up to ATTEMPTS times. A budget hit (3) and a security
# failure (4) are FATAL and are never retried; see the status contract above. Exits 1
# when attempts are exhausted.
#
# The phase's exit code is captured in the else branch: a completed `if` with no
# matching branch yields status 0, so reading $? after `fi` would swallow it.
e2e_run_with_retries() {
	_label=$1
	_attempts=$2
	_fn=$3
	case "$_attempts" in
		1 | 2 | 3) ;;
		*)
			printf 'FAIL: %s: attempts must be 1-3, got %s\n' "$_label" "$_attempts" >&2
			exit 1
			;;
	esac
	_n=0
	while true; do
		if "$_fn"; then
			return 0
		else
			_prc=$?
		fi
		if [ "$_prc" -eq "$E2E_STATUS_SECURITY" ]; then
			printf 'FAIL: %s phase FAILED A SECURITY ASSERTION; not retrying (a retry would erase the evidence)\n' "$_label" >&2
			exit 1
		fi
		if [ "$_prc" -eq "$E2E_STATUS_BUDGET" ]; then
			printf 'FAIL: %s phase hit the token budget; not retrying\n' "$_label" >&2
			exit 1
		fi
		_n=$((_n + 1))
		if [ "$_n" -ge "$_attempts" ]; then
			printf 'FAIL: %s phase failed after %d attempt(s)\n' "$_label" "$_n" >&2
			exit 1
		fi
		printf 'retry: %s phase attempt %d failed, retrying\n' "$_label" "$_n" >&2
	done
}

# e2e_assert_tool_called ERR - the footer must report a POSITIVE tool-call count.
# Matching a positive count (rather than rejecting "0 tool calls") also fails a
# missing or reshaped footer, which a negative check would quietly pass.
e2e_assert_tool_called() {
	if grep -Eq '(^|[^0-9])[1-9][0-9]* tool calls?' "$1"; then
		return 0
	fi
	printf 'no positive tool-call count in the footer (no tool work happened). stderr tail:\n' >&2
	tail -n 20 "$1" >&2
	return 1
}
