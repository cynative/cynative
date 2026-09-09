#!/bin/sh
# agent.e2e.test.sh - live built-in AGENT end-to-end test.
#
# Runs the real `cynative -p --agent gcp-public-bindings` against a real GCP
# fixture, proving the EMBEDDED built-in resolved from the binary, drove gated
# tool calls, produced a report, and stayed inside the read-only boundary. It is
# NOT a connector suite: the read phase hands the built-in a short project-level
# task rather than one spelled-out call, so its reads are not put through the
# connector audit sweep. The read phase does still bind BOTH of the task's reads to
# provider-returned evidence through the audit log, judged by
# test/lib/agent-witness.py (offline --selftest under `make sh-test`): an untruncated
# Cloud Resource Manager 200 for a GET of the fixture project's own record whose body
# carries GCP_E2E_EXPECT, the project number, fed out of band and never in the
# prompt, and an untruncated 200 for a POST of the project's getIamPolicy carrying
# a policy object. So a built-in that called an unrelated or failing endpoint and reported
# the failure cannot pass, and neither can one that skipped the policy read; any
# other reads are not swept. It DOES still run the shared
# credential prepass (the connector_audit engine's load_records + credential_prepass) over
# its own audit log, so a regression that logged the live LLM/Vertex credential during the
# built-in's read run fails the phase fatally even though no sanctioned-read sweep runs. The
# sweep itself is used only for a targeted single-call write canary (reusing the gcp spec).
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
#   GCP_E2E_EXPECT         fixture project number (NEVER in the prompt; the read
#                          phase binds it to the bytes Google returned)
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
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL GCP_E2E_PROJECT GCP_E2E_EXPECT \
	GOOGLE_APPLICATION_CREDENTIALS || exit 0

# The suite runs under an empty HOME (so no user agent shadows the built-in),
# which disables file-based ADC, so GOOGLE_APPLICATION_CREDENTIALS must name a
# readable creds file. Treat a set-but-unreadable path like a missing
# prerequisite: skip unless a run is required.
if [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
	if [ "${AGENT_E2E_REQUIRE_RUN:-}" = "1" ]; then
		echo "FAIL: GOOGLE_APPLICATION_CREDENTIALS is not a readable file but AGENT_E2E_REQUIRE_RUN=1" >&2
		exit 1
	fi
	echo "skip: agent.e2e (GOOGLE_APPLICATION_CREDENTIALS is not a readable file)" >&2
	exit 0
fi

# Go is only needed to build; a prebuilt binary passed as $1 skips the build.
[ -n "${1:-}" ] || e2e_require_cmd go "needed to build cynative" || exit 1
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
# The readable-creds-file precondition was already enforced before the build.
export HOME="$workdir/home"
mkdir -p "$HOME"
if [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
	echo "FAIL: GOOGLE_APPLICATION_CREDENTIALS is not readable" >&2
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
	# Hand the built-in a short task confined to this project, and tell it where to
	# stop. Its own prompt is organization-scoped (Cloud Asset searches, the
	# organization's project listing), which the fixture cannot serve: the CI service
	# account holds roles/viewer on this one project and the Cloud Asset API is not
	# enabled there. Left open-ended, the driver retries the denied organization reads
	# or repeats the ones that answered until the iteration cap, and every turn replays
	# a longer transcript into the token budget; the first release-gate run stopped at
	# 77k of 60k tokens with no answer. So the task names the two reads roles/viewer
	# serves and ends there: the project's own Cloud Resource Manager record, which the
	# witness check below binds to, and the project IAM policy. Measured before this
	# sentence was pinned, at 16 iterations, 200s and a 60k token budget: 10/10
	# gemini-3.5-flash runs finished in 2 to 6 model calls at 20k to 41k tokens, and a
	# four-read variant went 0/5, cut by the budget at 62k to 76k. The open-ended task,
	# run three times at the same cap and timeout with the budget lifted to 400k, never
	# stayed under 60k: two runs hit the iteration cap with no answer at 308k and 350k,
	# and one halted on the consecutive-failure summary at 75k. Re-measure the same way
	# before changing it. The project NUMBER is never named here: the model can only
	# surface it by actually reading the resource.
	_scope="Only project ${GCP_E2E_PROJECT}. This run covers that single project and nothing above it: skip the organization listing, Cloud Asset and every organization-scoped read. Read the project's own record from Cloud Resource Manager and note its project number, read the project's IAM policy, then write the report from those two reads and end."
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$_scope" --agent "$agent_name"; then _rc=0; else _rc=$?; fi

	# SECURITY prepass, BEFORE the classifier and every soft assertion. The witness
	# check below is positive-evidence only: it passes as long as a Cloud Resource
	# Manager 200 exists, so a regression that logged the live LLM/Vertex credential
	# during the built-in's open-ended read run would still green this phase. The
	# credential prepass that guards that is the SAME one connector_run_phase runs via
	# the parser in the canary phase - but the canary does not drive the agent, so the
	# agent's own read audit was never scanned. Run it here, over read.audit.log with
	# the base64 --live-secrets values in $secret_file (written at the top of the
	# script, before this phase runs). It reuses the engine directly - load_records +
	# credential_prepass from the snapshotted parser package, the two functions the
	# parser's dispatch() runs first on every sweep - the established heredoc-import
	# reuse pattern in this library (see _e2e_scrub_file in connector-e2e.sh). python3
	# -B so importing the package writes no __pycache__ into the snapshot.
	#
	# It mirrors connector_run_phase's ordering: a security breach (4) DOMINATES a
	# timeout (2) or a budget stop (3), so it runs before e2e_classify_run and
	# short-circuits it. Any nonzero exit - a real credential-prepass 4, a fail-closed
	# load_records, or the guard mapping an unexpected crash to 4 - is a fatal 4, never
	# a retryable miss (a retry truncates the audit and would erase the evidence).
	if ! python3 -B - "$workdir/connector_audit_pkg" "$secret_file" "$workdir/read.audit.log" <<'PY'
import sys

pkg, secrets_path, audit = sys.argv[1], sys.argv[2], sys.argv[3]
sys.dont_write_bytecode = True
sys.path.insert(0, pkg)
try:
    from connector_audit.engine import credential_prepass, load_records
    records, raw_lines = load_records(audit)
    credential_prepass(records, raw_lines, secrets_path)
except SystemExit:
    raise  # the engine's own insecure()/die() exit code (4 on a hit) - a real verdict.
except BaseException as e:  # noqa: BLE001 - any unexpected failure fails closed to 4.
    print("SECURITY: agent read credential prepass crashed (%s: %s) - failing closed"
          % (type(e).__name__, e))
    sys.exit(4)
print("read credscan: OK (no live credential material in the agent read audit)", file=sys.stderr)
PY
	then
		echo "FAIL: SECURITY: the agent read audit contains live credential material (credential prepass); not retrying" >&2
		return 4
	fi

	# Classify (timeout 2 retryable / budget 3 fatal / miss) only after the security
	# prepass held, so a timeout or budget stop is propagated before any soft assertion
	# turns it into another paid attempt.
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
	# The report is bound to provider-returned bytes. Everything above is satisfied by
	# a broken built-in that called an unrelated or failing endpoint and then reported
	# the failure: the tool-call count is positive and stdout is nonempty either way.
	# So require both of the task's reads from the write-ahead audit log, judged by
	# test/lib/agent-witness.py from the checkout under test: a GET of the project's
	# own Cloud Resource Manager record (path /v1/projects/{id} or /v3/projects/{id},
	# nothing appended) that returned an untruncated 200 whose BODY carries
	# GCP_E2E_EXPECT, and a POST of the project's getIamPolicy that returned an
	# untruncated 200 carrying a policy object. The record witness is pinned to its method and
	# exact path because the policy response is on the same host with the same id in
	# its URL and carries the project number inside the service-agent principals; the
	# policy witness is audit evidence that the built-in's own read happened, where a
	# check on the report's prose would be satisfied by the agent's description alone.
	# The helper is lenient where the connector audit engine fails closed (an unusable
	# record is skipped, never fatal, since these are positive-evidence assertions) and
	# strict about the evidence itself; its --selftest pins every branch offline.
	if ! python3 -B "$root/test/lib/agent-witness.py" "$GCP_E2E_PROJECT" "$GCP_E2E_EXPECT" "$workdir/read.audit.log"; then
		echo "FAIL: the audit log does not witness both task reads (see the MISSING line above)" >&2
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
