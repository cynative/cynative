#!/bin/sh
# agent.e2e.test.sh - live built-in AGENT end-to-end test.
#
# Runs the real `cynative -p --agent gcp-public-bindings` against a real GCP
# fixture, proving the EMBEDDED built-in resolved from the binary, drove gated
# tool calls, produced a report, and stayed inside the read-only boundary. It is
# NOT a connector suite: an agent run is open-ended, so its reads are not put
# through the connector audit sweep. The read phase does still bind ONE fixture
# read to provider-returned evidence through the audit log (an untruncated Cloud
# Resource Manager 200 for the fixture project whose body carries GCP_E2E_EXPECT,
# the project number, fed out of band and never in the prompt), so a built-in that
# called an unrelated or failing endpoint and reported the failure cannot pass; the
# open-ended reads that follow are otherwise not swept. The sweep is used only for
# a targeted single-call write canary (reusing the gcp spec).
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
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL GCP_E2E_PROJECT GCP_E2E_EXPECT || exit 0

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
	# iteration and token caps against a single-project fixture, and nudge it to open
	# with the project's own Cloud Resource Manager record. roles/viewer grants that
	# read, so a working build always produces one successful fixture read the witness
	# check below can bind to, even though the org-scoped reads the agent goes on to
	# make are denied by the ceiling. The project NUMBER is never named here: the
	# model can only surface it by actually reading the resource.
	_scope="Only project ${GCP_E2E_PROJECT}. Begin by reading that project's own record from Cloud Resource Manager and note its project number, then continue the research and report what you can read."
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
	# The report is bound to provider-returned bytes. Everything above is satisfied by
	# a broken built-in that called an unrelated or failing endpoint and then reported
	# the failure: the tool-call count is positive and stdout is nonempty either way.
	# So require, from the write-ahead audit log, one http_request whose Cloud Resource
	# Manager call for the fixture project came back an untruncated 200 whose BODY
	# carries GCP_E2E_EXPECT (the project number, fed out of band, never in the prompt).
	#
	# The detection mirrors test/lib/connector_audit/specs/gcp.py's is_witness and the
	# engine helpers it uses (args_of, status_of, body_of); it is inline rather than a
	# parser call because this suite deliberately runs no sweep over an open-ended
	# agent's reads. It is LENIENT where the engine fails closed - an unreadable,
	# malformed, duplicate-keyed, fold-colliding or unpaired record is skipped, not
	# fatal - because this is a positive-evidence assertion and skipping a record can
	# only make it HARDER to pass. It is strict about the evidence itself: a status
	# that merely looks like 200, a truncated body, or the value appearing in a
	# response HEADER rather than the body must never mint a witness.
	if ! python3 - "$GCP_E2E_PROJECT" "$GCP_E2E_EXPECT" "$workdir/read.audit.log" <<'PY'
import json
import re
import sys

project, expect, path = sys.argv[1], sys.argv[2], sys.argv[3]
CRM = "cloudresourcemanager.googleapis.com"


def _no_dup(pairs):
    """Reject a duplicate JSON key: which value Go bound is decoder-internal, so the
    record is ambiguous and must not be read as evidence."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key %r" % k)
        out[k] = v
    return out


def loads(s):
    return json.loads(s, object_pairs_hook=_no_dup)


def text(v):
    return v if isinstance(v, str) else ""


def args_of(rec):
    """The record's arguments with keys case-folded the way Go's encoding/json binds
    them (a miscased "URL" is still the url on the wire), or None when unusable."""
    a = rec.get("arguments")
    if isinstance(a, str):
        try:
            a = loads(a)
        except ValueError:
            return None
    if not isinstance(a, dict):
        return None
    out = {}
    for k, v in a.items():
        f = k.casefold() if isinstance(k, str) else k
        if f in out:
            return None
        out[f] = v
    return out


def result_json(rec):
    """The sandbox path records StructuredRun's JSON as a STRING, so result needs a
    second decode. The direct path records the raw dump, which starts with the status
    line and so can never be mistaken for the structured wrapper."""
    try:
        obj = loads(text(rec.get("result")))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def status_of(rec):
    obj = result_json(rec)
    # type(x) is int, not isinstance: isinstance(True, int) is True in Python, so an
    # isinstance check would let a JSON bool masquerade as a status.
    if obj is not None and type(obj.get("status")) is int:
        return obj["status"]
    # Anchor on the protocol version and require a boundary after the 3-digit status
    # so "HTTP/1.1 2000" cannot be read as 200.
    m = re.match(r"HTTP/[0-9.]+\s+([0-9]{3})(?![0-9])", text(rec.get("result")))
    return int(m.group(1)) if m else None


def body_of(rec):
    """(body, truncated). Fail-closed on the structured path: a missing/non-false
    truncated flag, a non-string body or a non-int status counts as truncated. On the
    direct path the dump carries the status line and headers before the body, so cut
    them off - a marker appearing only in a response HEADER is not the provider's
    body and must not satisfy the assertion."""
    obj = result_json(rec)
    if obj is not None and ("status" in obj or "body" in obj or "truncated" in obj):
        body = obj.get("body")
        ok = (obj.get("truncated") is False and isinstance(body, str)
              and type(obj.get("status")) is int)
        return (body if isinstance(body, str) else ""), (not ok)
    dump = text(rec.get("result"))
    truncated = "[Response truncated at" in dump
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in dump:
            return dump.split(sep, 1)[1], truncated
    return "", truncated


try:
    raw = open(path, encoding="utf-8").read()
except (OSError, UnicodeDecodeError):
    sys.exit(1)

attempts = {}
results = []
for line in raw.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        rec = loads(line)
    except ValueError:
        continue
    if not isinstance(rec, dict) or rec.get("tool") != "http_request":
        continue
    key = (rec.get("session_id"), rec.get("run_id"), rec.get("call_id"))
    if not all(isinstance(k, str) and k for k in key):
        continue
    if rec.get("phase") == "attempt":
        attempts[key] = rec
    elif rec.get("phase") == "result":
        results.append((key, rec))

# The url comes from the ATTEMPT (write-ahead: it lands before the request runs) and
# the response from the matching RESULT; an unpaired result proves nothing about what
# was dispatched, so it is skipped.
for key, rec in results:
    attempt = attempts.get(key)
    if attempt is None:
        continue
    a = args_of(attempt)
    if a is None:
        continue
    url = text(a.get("url"))
    if CRM not in url or project not in url:
        continue
    if status_of(rec) != 200:
        continue
    body, truncated = body_of(rec)
    if truncated or expect not in body:
        continue
    print("read witness: OK (a Cloud Resource Manager 200 for %s carried the expected "
          "value)" % project, file=sys.stderr)
    sys.exit(0)
sys.exit(1)
PY
	then
		echo "FAIL: no witnessed Cloud Resource Manager 200 for the fixture project carrying the expected value" >&2
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
