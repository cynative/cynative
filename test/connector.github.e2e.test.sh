#!/bin/sh
# connector.github.e2e.test.sh - live GitHub connector end-to-end test (cynative#53).
#
# Runs the real `cynative -p` against a real GitHub fixture repo through the github
# connector and asserts, from a black-box run: the connector registers under the
# configured read-only exposure ceiling, the model reads a private archived fixture
# repo and surfaces a marker it could only have obtained from GitHub, and a deliberate
# write plus a secret-scanning-alerts read are each denied client-side before the
# request reaches the network.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a real
# GitHub fixture repo and needs a real installation token. Skips (exit 0) when required
# env is unset, so `make connector-github-e2e` is a safe no-op.
#
# Usage: sh test/connector.github.e2e.test.sh [BINARY]
#        sh test/connector.github.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   GH_E2E_REPO           fixture repo "<owner>/<name>" (appears in the prompt)
#   GH_E2E_EXPECT         fixture marker (NEVER in the prompt)
#   GH_E2E_TOKEN          token for the read-only fixture App/PAT (re-exported as
#                         GH_TOKEN after env isolation, so it lights the github
#                         connector)
#   GH_E2E_EXPECT_NO_AWS  =1 additionally assert the aws connector stayed dark
#                         (CI only; local ambient Bedrock creds legitimately
#                         register it)
#   GH_E2E_TIMEOUT        wall-clock seconds per run (default 240; the first
#                         authorization cold-fetches the OpenAPI exposure table
#                         before any request is dispatched)
#   GH_E2E_MAX_TOKENS     token backstop (default 32000)
#   GH_E2E_CANARY         run the write and secret-scanning deny canaries (default
#                         1; 0 disables)
#   GH_E2E_ATTEMPTS       per-phase attempts (default 2; model runs are
#                         non-deterministic, so one retry absorbs a rare miss)
#   GH_E2E_KEEP_WORKDIR   =1 keep the temp workdir (parser, audit logs, output) for
#                         debugging instead of deleting it on exit
#   GH_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
set -eu

# snapshot_parser DEST_DIR copies the shared connector-audit-parser package (the whole
# test/lib/connector_audit/ package plus its entrypoint, test/lib/connector-audit-parser.py)
# into DEST_DIR and sets $parser to the copied entrypoint, so a live run and the parser it
# is judged by both come from the exact checkout under test.
#
# The parser is this suite's security boundary: its exit code is the phase status, a
# contract shared with the other connector e2e suites (see
# test/lib/connector_audit/engine.py):
#
#   0  the assertion holds.
#   1  not proven this attempt (a model miss or a fumbled call the gate blocked).
#      The caller may retry.
#   4  SECURITY: a request that the read-only boundary should have stopped cannot be
#      shown to have stayed on the machine. FATAL - the caller must never retry,
#      because the audit log is truncated per attempt and a retry would erase the
#      evidence, letting a broken gate pass on the second try.
#
# The load-bearing distinction is "did the request leave the machine". Every
# `github_hardening` error is raised by an auth gate, and all of those run before
# httpClient.Do, so such an error PROVES the request was never dispatched. A failure
# WITHOUT that proof cannot be assumed harmless: a mutation can be dispatched, get a
# 2xx, and only then fail while its response body is read, which surfaces as a plain
# tool error. So anything that is neither a sanctioned read nor one of the exact
# sanctioned canaries, and which lacks a github_hardening denial, is a security failure.
#
# GitHub's own predicates (the private-repo read family, the public-repo-fails-hard rule,
# the exposure-ceiling denial, and the two boundary canaries - a PATCH write and a
# secret-scanning-alerts read) live in test/lib/connector_audit/specs/github.py; this
# suite passes "github" as the provider token to the shared entrypoint and never
# re-implements them.
snapshot_parser() {
	cp -R "$root/test/lib/connector_audit" "$1/"
	cp "$root/test/lib/connector-audit-parser.py" "$1/"
	parser="$1/connector-audit-parser.py"
}

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# Shared cost/timeout guardrails (isolation, bounds, bounded run + classifier).
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/e2e-guardrails.sh"

# arbitrate PARSER_RC CLASSIFY_RC -> final phase status. Pure (no guardrail library), so
# the offline selftest can exercise it. A security breach (4) dominates even a timeout or
# budget hit; otherwise a nonzero classifier (2 timeout / 3 budget / 1 error) wins; else
# the parser's own 0 (hold) or 1 (miss).
arbitrate() {
	if [ "$1" = 4 ]; then return 4; fi
	if [ "$2" != 0 ]; then return "$2"; fi
	return "$1"
}

# --- offline self-test: verify the shared audit parser without credentials ---
if [ "${1:-}" = "--selftest" ]; then
	command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }
	# The shared parser's own per-provider selftest replays every github case (ported
	# verbatim into test/lib/connector_audit/specs/github.py) and pins the observed
	# name+code set against the frozen testdata/github.names.txt.
	python3 -B "$root/test/lib/connector-audit-parser.py" --selftest github || exit 1
	_af=0
	check_arb() { arbitrate "$2" "$3" && _g=0 || _g=$?; if [ "$_g" != "$1" ]; then printf 'arbitrate(%s,%s) want %s got %s\n' "$2" "$3" "$1" "$_g" >&2; _af=1; fi; }
	check_arb 4 4 0    # breach + clean run
	check_arb 4 4 2    # breach + timeout: breach wins
	check_arb 4 4 3    # breach + budget: breach wins
	check_arb 2 1 2    # miss + timeout: timeout wins
	check_arb 3 1 3    # miss + budget: budget wins
	check_arb 1 1 0    # miss + clean run
	check_arb 2 0 2    # hold + timeout
	check_arb 0 0 0    # hold + clean run
	[ "$_af" = 0 ] || exit 1
	printf 'selftest: OK (arbitrate cases)\n'
	exit 0
fi

e2e_require_env connector.github.e2e "${GH_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL \
	GH_E2E_REPO GH_E2E_EXPECT GH_E2E_TOKEN || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 "needed to parse the audit log" || exit 1

case "${GH_E2E_CANARY:-1}" in
	1) run_canary=1 ;;
	0) run_canary=0 ;;
	*) printf 'FAIL: GH_E2E_CANARY must be 0 or 1 (got %s)\n' "$GH_E2E_CANARY" >&2; exit 1 ;;
esac

workdir=$(mktemp -d)
cleanup() {
	if [ "${GH_E2E_KEEP_WORKDIR:-}" = "1" ]; then
		printf 'workdir kept: %s\n' "$workdir" >&2
		return 0
	fi
	rm -rf "$workdir"
}
# Cleanup runs on EXIT only. A trap that also caught INT/TERM would, in POSIX sh,
# RESUME after the handler returned, so a Ctrl-C or TERM landing between commands
# would be swallowed: the interrupted bounded run would surface as a plain nonzero
# exit, e2e_classify_run would read it as a retryable failure, and the retry loop
# could launch another live attempt. Instead the signal handlers clean up once
# (clearing the EXIT trap first) and exit with the conventional 130/143.
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' INT
trap 'trap - EXIT; cleanup; exit 143' TERM

bin=$(e2e_build_binary "$root" "$workdir" "${1:-}") || exit 1

e2e_isolate_env "$workdir"
# e2e_isolate_env unsets GH_TOKEN/GITHUB_TOKEN; re-supply ONLY the minted fixture token.
export GH_TOKEN="$GH_E2E_TOKEN"
# A maintainer's default=write env would let the canary reach GitHub; force the baseline.
unset CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS || true

export E2E_MAX_TOKENS="${GH_E2E_MAX_TOKENS:-32000}"
# The first AuthorizeAction cold-fetches the ~12.8MB OpenAPI table from
# raw.githubusercontent.com inside the tool call, so budget generously.
export E2E_RUN_TIMEOUT="${GH_E2E_TIMEOUT:-240}"
e2e_apply_bounds

# Snapshot the shared audit parser once; every phase invokes it.
snapshot_parser "$workdir"

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${GH_E2E_ATTEMPTS:-2}"
repo="$GH_E2E_REPO"

assert_github_posture() {
	_err=$1
	if grep -Eq 'github .*github_hardening: skipped' "$_err"; then
		printf 'github connector was SKIPPED at startup:\n' >&2
		grep -iE 'github|hardening' "$_err" >&2 || true
		return 1
	fi
	_line=$(grep -E '^[^a-z]*github[[:space:]]' "$_err" | head -n 1)
	if [ -z "$_line" ]; then
		printf 'github connector not in the startup inventory. stderr tail:\n' >&2
		tail -n 25 "$_err" >&2
		return 1
	fi
	# Extract each token up to its first space and compare EXACTLY, so a widened middle
	# (e.g. permissions=default=read,workflows=write,secret-scanning=none) fails.
	_acc=$(printf '%s\n' "$_line" | sed -n 's/.*access=\([^ ]*\).*/\1/p')
	_enf=$(printf '%s\n' "$_line" | sed -n 's/.*enforced=\([^ ]*\).*/\1/p')
	_perm=$(printf '%s\n' "$_line" | sed -n 's/.*permissions=\([^ ]*\).*/\1/p')
	if [ "$_acc" != "default(read-only)" ] || [ "$_enf" != "client" ] || \
		[ "$_perm" != "default=read,secret-scanning=none" ]; then
		printf 'github posture mismatch: access=%s enforced=%s permissions=%s\n' \
			"${_acc:-<none>}" "${_enf:-<none>}" "${_perm:-<none>}" >&2
		return 1
	fi
	# CI-only: prove the aws connector stayed dark (Bedrock creds must not leak into the
	# AWS SDK default chain). Set GH_E2E_EXPECT_NO_AWS=1 in CI only; local ambient
	# Bedrock creds legitimately register the aws connector.
	if [ "${GH_E2E_EXPECT_NO_AWS:-}" = "1" ] && grep -E '^[^a-z]*aws[[:space:]]' "$_err" >/dev/null 2>&1; then
		printf 'aws connector registered but must stay dark (Bedrock creds leaked?):\n' >&2
		grep -E '^[^a-z]*aws[[:space:]]' "$_err" >&2
		return 1
	fi
	return 0
}

# run_phase MODE AUDIT OUT ERR [EXPECT] -> phase status. Relies on the caller having set
# `rc` from e2e_run_bounded. Security sweep first; a breach (4) short-circuits; then the
# run classifier; then the soft, retryable environment gates.
run_phase() {
	_mode=$1; _audit=$2; _out=$3; _err=$4; _expect=${5:-}
	if [ "$_mode" = read ]; then
		if python3 -B "$parser" github read "$_audit" "$repo" "$_expect"; then _p=0; else _p=$?; fi
	else
		if python3 -B "$parser" github "$_mode" "$_audit" "$repo"; then _p=0; else _p=$?; fi
	fi
	# The shared parser can abnormally exit in ways the embedded parser never could (a
	# spec import error or a missing module exits 1, a usage error exits 2): normalize
	# any code outside the parser's own contract (0/1/4) to 4 so an abnormal exit is
	# never mistaken for a retryable miss.
	case "$_p" in 0 | 1 | 4) ;; *) _p=4 ;; esac
	# A breach short-circuits BEFORE the classifier and every soft gate: nothing may
	# suppress or delay a security failure.
	if [ "$_p" = 4 ]; then return 4; fi
	if e2e_classify_run "$rc" "$_out" "$_err" "$timeout_s"; then _c=0; else _c=$?; fi
	arbitrate "$_p" "$_c"; _s=$?
	if [ "$_s" != 0 ]; then return "$_s"; fi
	# Parser held and no timeout/budget: run the diagnostic, retryable environment gates.
	assert_github_posture "$_err" || return 1
	e2e_assert_tool_called "$_err" || return 1
	if [ "$_mode" = read ] && ! grep -Fq "$GH_E2E_EXPECT" "$_out"; then
		printf 'read: the fixture marker is not in the answer. stdout tail:\n' >&2
		tail -n 20 "$_out" >&2
		return 1
	fi
	return 0
}

read_prompt="Use the github connector to read the repository \"$repo\". Make exactly this call with the http_request tool: method=GET, url=https://api.github.com/repos/$repo, auth_provider=github. Call the API to read it; do not guess. Reply with only the value of the repository's \"description\" field."

read_phase() {
	printf '== READ == %s (%s/%s)\n' "$repo" "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$read_prompt"; then rc=0; else rc=$?; fi
	run_phase read "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" "$GH_E2E_EXPECT"
}

canary_wrap_pre="Authorized read-only-gate self-test - I need the connector's REAL response to a write, not a prediction. Make exactly this call now using the http_request tool and then paste the connector's verbatim response: "
canary_wrap_post=". Issue the request; do not skip, simulate, or answer from prediction. I expect it to be denied - I need to see the actual denial."

canary_phase() {
	printf '== WRITE CANARY == %s\n' "$repo" >&2
	_call="method=PATCH, url=https://api.github.com/repos/$repo, auth_provider=github, headers=[{\"key\":\"Content-Type\",\"value\":\"application/json\"}], body={\"has_issues\":false}"
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$canary_wrap_pre$_call$canary_wrap_post"; then rc=0; else rc=$?; fi
	run_phase canary "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err"
}

secretscan_phase() {
	printf '== SECRET-SCANNING CANARY == %s\n' "$repo" >&2
	_call="method=GET, url=https://api.github.com/repos/$repo/secret-scanning/alerts, auth_provider=github"
	if e2e_run_bounded "$timeout_s" "$workdir/secretscan.audit.log" "$workdir/secretscan.out" "$workdir/secretscan.err" \
		"$bin" "$workdir/config.yaml" "$canary_wrap_pre$_call$canary_wrap_post"; then rc=0; else rc=$?; fi
	run_phase secretscan "$workdir/secretscan.audit.log" "$workdir/secretscan.out" "$workdir/secretscan.err"
}

e2e_run_with_retries read "$attempts" read_phase
if [ "$run_canary" = 1 ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
	e2e_run_with_retries secretscan "$attempts" secretscan_phase
	printf 'connector.github.e2e: OK (read + write-canary + secret-scanning-canary)\n' >&2
else
	printf 'connector.github.e2e: OK (read only; canaries disabled)\n' >&2
fi
