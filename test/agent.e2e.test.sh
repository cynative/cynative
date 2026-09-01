#!/bin/sh
# agent.e2e.test.sh - live built-in AGENT end-to-end test.
#
# Runs the real `cynative -p --agent gcp-public-bindings` against a real GCP
# fixture, proving the EMBEDDED built-in resolved from the binary, drove gated
# tool calls, produced a report, and stayed inside the read-only boundary. It is
# NOT a connector suite: an agent run is open-ended, so its reads are not put
# through the connector audit sweep. The sweep is used only for a targeted
# single-call write canary (reusing the gcp spec).
#
# NOT hermetic and NOT part of `make check`. Skips (exit 0) when the fixture env
# is unset, unless AGENT_E2E_REQUIRE_RUN=1.
#
# Usage: sh test/agent.e2e.test.sh [BINARY]
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   GOOGLE_APPLICATION_CREDENTIALS              readable GCP creds file (the suite
#                                               runs under an empty HOME, so file
#                                               ADC in ~ is not consulted)
#   GCP_E2E_PROJECT        fixture project id (used only to scope the agent run)
#   AGENT_E2E_TIMEOUT      wall-clock seconds per run (default 240)
#   AGENT_E2E_MAX_TOKENS   token backstop (default 60000)
#   AGENT_E2E_CANARY       run the write-deny canary phase (0 or 1; default 1)
#   AGENT_E2E_ATTEMPTS     per-phase attempts before failing (default 2)
#   AGENT_E2E_REQUIRE_RUN  =1 hard-fail instead of skipping when required env is unset
#   AGENT_E2E_KEEP_WORKDIR =1 keep the temp workdir (its path is printed) for debugging
set -eu

# The built-in under test. A single variable so the agent can be swapped in one
# place if the live confirmation run (Step 3) shows it halts against the fixture.
agent_name=gcp-public-bindings

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$root/test/lib/connector-e2e.sh"

# Copy the audit parser into the workdir so the canary phase can run it offline.
snapshot_parser() {
	_dst="$1/connector_audit_pkg"
	mkdir -p "$_dst"
	cp -R "$root/test/lib/connector_audit" "$_dst/"
	cp "$root/test/lib/connector-audit-parser.py" "$_dst/"
	parser="$_dst/connector-audit-parser.py"
}

e2e_require_env agent.e2e "${AGENT_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL GCP_E2E_PROJECT || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 || exit 1
e2e_require_cmd base64 || exit 1

# Validate the canary vocabulary up front (0 or 1); any other value must not
# silently skip the security phase.
run_canary="${AGENT_E2E_CANARY:-1}"
case "$run_canary" in
	0 | 1) ;;
	*) echo "FAIL: AGENT_E2E_CANARY must be 0 or 1, got '$run_canary'" >&2; exit 1 ;;
esac

workdir=$(mktemp -d)
secret_file=""
cleanup() {
	[ -n "$secret_file" ] && rm -f "$secret_file"
	if [ "${AGENT_E2E_KEEP_WORKDIR:-}" = "1" ]; then
		printf 'agent.e2e: kept workdir %s\n' "$workdir" >&2
	else
		rm -rf "$workdir"
	fi
}
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' INT
trap 'trap - EXIT; cleanup; exit 143' TERM

# Build first (needs the real HOME for the Go cache), THEN isolate.
bin=$(e2e_build_binary "$root" "$workdir" "${1:-}") || exit 1

e2e_isolate_env "$workdir"
unset CYNATIVE_CONNECTORS_GCP_ROLE || true

# Empty HOME so no user-tier agent in ~/.cynative/agents can shadow the built-in.
# Moving HOME also disables file-based ADC, so require an explicit readable creds file.
export HOME="$workdir/home"
mkdir -p "$HOME"
if [ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] || [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
	echo "FAIL: GOOGLE_APPLICATION_CREDENTIALS must point at a readable creds file (empty HOME disables ADC)" >&2
	exit 1
fi

export E2E_MAX_TOKENS="${AGENT_E2E_MAX_TOKENS:-60000}"
export E2E_RUN_TIMEOUT="${AGENT_E2E_TIMEOUT:-240}"
e2e_apply_bounds
e2e_pin_audit_size

snapshot_parser "$workdir"

secret_file=$(mktemp)
e2e_write_live_secrets "$secret_file" CYNATIVE_LLM_API_KEY CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${AGENT_E2E_ATTEMPTS:-2}"

assert_gcp_posture() {
	_err="$1"
	if grep -Eq 'gcp .*gcp_hardening: skipped' "$_err"; then
		echo "FAIL: gcp connector reported gcp_hardening: skipped" >&2
		return 1
	fi
	if ! grep -Eq 'gcp .*role=roles/viewer' "$_err"; then
		echo "FAIL: gcp connector posture is not role=roles/viewer" >&2
		return 1
	fi
	return 0
}

read_phase() {
	# Scope the open-ended agent to this project so it stays inside the guardrail
	# iteration and token caps against a single-project fixture.
	_scope="Only project ${GCP_E2E_PROJECT}; report what you can read for this project."
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$_scope" --agent "$agent_name"; then _rc=0; else _rc=$?; fi

	# Classify FIRST, so a timeout (2, retryable) or a budget stop (3, fatal) is
	# propagated before any soft assertion turns it into another paid attempt.
	e2e_classify_run "$_rc" "$workdir/read.out" "$workdir/read.err" "$timeout_s"
	_cls=$?
	[ "$_cls" = 0 ] || return "$_cls"

	# The run produced an answer. Now the agent-agnostic soft assertions.
	# The embedded built-in must have resolved (not a user file). Exact match: the
	# source word is "builtin" (no hyphen), the path prefix is "built-in", two spaces.
	if ! grep -Fqx "  Agent: ${agent_name}  [builtin: built-in/${agent_name}.md]" "$workdir/read.err"; then
		echo "FAIL: built-in provenance line for ${agent_name} not found on stderr" >&2
		return 1
	fi

	# Posture proves the gcp connector authenticated LIVE this startup (the line only
	# appears for a validated connector) and stayed read-only.
	assert_gcp_posture "$workdir/read.err" || return 1
	# The agent drove gated tool calls.
	e2e_assert_tool_called "$workdir/read.err" || return 1
	# It produced a report.
	if [ ! -s "$workdir/read.out" ]; then
		echo "FAIL: agent produced no report on stdout" >&2
		return 1
	fi
	return 0
}

canary_phase() {
	printf '== CANARY == attempting a denied write on %s\n' "$GCP_E2E_PROJECT" >&2
	# Exact call the gcp audit parser sanctions as the deny target (copied verbatim
	# from test/connector.gcp.e2e.test.sh; keep _call on one line).
	_call="method=PATCH, url=https://cloudresourcemanager.googleapis.com/v3/projects/$GCP_E2E_PROJECT?updateMask=labels, auth_provider=gcp, gcp_auth={service: cloudresourcemanager}, body={\"labels\":{\"cynative-e2e\":\"canary\"}}"
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$(e2e_canary_prompt "$_call")"; then _rc=0; else _rc=$?; fi
	connector_run_phase gcp canary "$parser" "$workdir/canary.audit.log" \
		"$workdir/canary.out" "$workdir/canary.err" "$_rc" "$timeout_s" \
		assert_gcp_posture "$GCP_E2E_PROJECT" "" "$secret_file"
}

e2e_run_with_retries read "$attempts" read_phase

if [ "$run_canary" = "1" ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
fi

printf 'agent.e2e: OK (%s)\n' "$agent_name"
