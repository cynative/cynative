# shellcheck shell=sh
# e2e-guardrails.sh - shared cost/timeout guardrails for the live e2e suites
# (cynative#51). Sourced, never executed: it defines helpers and has no side
# effects at source time, so an offline caller (e.g. the connector script's
# --selftest) can source it safely.
#
# It keeps the two live suites - test/llm.smoke.test.sh and
# test/connector.gcp.e2e.test.sh - on one bounded configuration so a broken live
# run cannot quietly burn credits, hang a runner, or leave a maintainer guessing.
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
	unset GH_CONFIG_DIR GLAB_CONFIG_DIR KUBECONFIG \
		GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN GITLAB_ACCESS_TOKEN OAUTH_TOKEN
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
