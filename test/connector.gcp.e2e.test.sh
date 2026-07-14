#!/bin/sh
# connector.gcp.e2e.test.sh - live GCP connector end-to-end test (cynative#39).
#
# Runs the real `cynative -p` against a real GCP fixture project through the gcp
# connector and asserts, from a black-box run: the connector registers read-only,
# the model reads the project's own Cloud Resource Manager metadata (surfacing the
# stable project number), and a deliberate write is denied client-side before it
# leaves the machine. The read-only guarantee rests on the enforced roles/viewer
# role plus cynative's client-side action gate; the write-deny canary is the
# positive boundary proof.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a
# real GCP project and needs real credentials. Skips (exit 0) when required env is
# unset, so `make connector-gcp-e2e` is a safe no-op.
#
# Usage: sh test/connector.gcp.e2e.test.sh [BINARY]
#        sh test/connector.gcp.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   GOOGLE_APPLICATION_CREDENTIALS              GCP ADC so the gcp connector registers
#   GCP_E2E_PROJECT                             fixture project id (in the prompt + read URL)
#   GCP_E2E_EXPECT                              fixture project number (NEVER in the prompt)
#   GCP_E2E_TIMEOUT        wall-clock seconds per run (default 120)
#   GCP_E2E_MAX_TOKENS     token backstop (default 32000)
#   GCP_E2E_CANARY         run the write-deny canary phase (default 1; 0 disables)
#   GCP_E2E_ATTEMPTS       per-phase attempts before failing (default 2; model runs
#                          are non-deterministic, so one retry absorbs a rare miss)
#   GCP_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
set -eu

# write_parser writes the embedded python3 audit parser to $1. The parser reads a
# JSONL audit log and, for `read`, confirms a successful gcp GET to Cloud Resource
# Manager for the project; for `canary`, confirms the marked write was attempted
# and denied client-side (never dispatched).
write_parser() {
	cat >"$1" <<'PY'
import json
import sys
from urllib.parse import urlparse

mode = sys.argv[1]
path = sys.argv[2]


def result_http_records(p):
    out = []
    with open(p) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("tool") == "http_request" and rec.get("phase") == "result":
                out.append(rec)
    return out


def arg(rec, key):
    a = rec.get("arguments")
    return a.get(key) if isinstance(a, dict) else None


def args_text(rec):
    a = rec.get("arguments")
    return a if isinstance(a, str) else json.dumps(a)


def read_hit(r, project):
    # A successful gcp GET to Cloud Resource Manager that references the project.
    # Host-anchored (not a bare substring) but endpoint-agnostic: different models
    # read a project differently - a direct get (/v1/projects/<p>, project in the
    # path) or a filtered list (/v1/projects?filter=name:<p>, project in the query).
    # Both are valid reads that surface the number; project-specificity is also
    # pinned by the stdout project-number assertion.
    if (arg(r, "method") or "").upper() != "GET":
        return False
    if arg(r, "auth_provider") != "gcp":
        return False
    if r.get("outcome") != "ok":
        return False
    u = arg(r, "url") or ""
    if urlparse(u).hostname != "cloudresourcemanager.googleapis.com":
        return False
    return project in u


recs = result_http_records(path)

if mode == "read":
    project = sys.argv[3]
    hits = [r for r in recs if read_hit(r, project)]
    if not hits:
        print("audit(read): no successful gcp GET to cloudresourcemanager for %s" % project)
        sys.exit(1)
    print("audit(read): OK (%d matching GET)" % len(hits))
    sys.exit(0)

if mode == "canary":
    marker = "cynative-e2e"
    marked = [r for r in recs if marker in args_text(r)]
    if not marked:
        print("audit(canary): no marked (%s) write found - the boundary was never exercised" % marker)
        sys.exit(1)
    for r in marked:
        if r.get("outcome") == "ok":
            print("audit(canary): a marked write SUCCEEDED - the read-only gate failed")
            sys.exit(1)
        # Require an explicit client-side gate denial: outcome error AND the
        # gcp_hardening text. A server 4xx (dispatched then rejected) or any other
        # error kind means the request may have left the machine.
        if not (r.get("outcome") == "error" and "gcp_hardening" in (r.get("result") or "")):
            print("audit(canary): a marked write was not denied client-side (need outcome=error + gcp_hardening): outcome=%s" % r.get("outcome"))
            sys.exit(1)
    print("audit(canary): OK (%d marked, all denied client-side)" % len(marked))
    sys.exit(0)

print("audit: unknown mode %r" % mode)
sys.exit(2)
PY
}

# selftest exercises the parser offline against synthetic audit logs. --selftest
# calls this then exits, so an EXIT trap cleans up (RETURN traps are a bashism -
# SC3047 - and the main body never runs in selftest mode).
selftest() {
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT INT TERM
	command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }
	p="$td/parser.py"
	write_parser "$p"

	url='https://cloudresourcemanager.googleapis.com/v1/projects/demo-proj'
	# A good read: successful gcp GET.
	printf '%s\n' \
		"{\"tool\":\"http_request\",\"phase\":\"result\",\"arguments\":{\"method\":\"GET\",\"url\":\"$url\",\"auth_provider\":\"gcp\"},\"outcome\":\"ok\",\"result\":\"{}\"}" \
		>"$td/read_ok.log"
	# A bad read: the GET failed.
	printf '%s\n' \
		"{\"tool\":\"http_request\",\"phase\":\"result\",\"arguments\":{\"method\":\"GET\",\"url\":\"$url\",\"auth_provider\":\"gcp\"},\"outcome\":\"error\",\"result\":\"boom\"}" \
		>"$td/read_bad.log"
	# A good read via a filtered list (project id in the query, not the path):
	# a different-but-valid read endpoint some models use.
	list_url='https://cloudresourcemanager.googleapis.com/v1/projects?filter=name:demo-proj'
	printf '%s\n' \
		"{\"tool\":\"http_request\",\"phase\":\"result\",\"arguments\":{\"method\":\"GET\",\"url\":\"$list_url\",\"auth_provider\":\"gcp\"},\"outcome\":\"ok\",\"result\":\"{}\"}" \
		>"$td/read_list.log"
	# Canary denied client-side (good): marked write, outcome error, gcp_hardening.
	printf '%s\n' \
		"{\"tool\":\"http_request\",\"phase\":\"result\",\"arguments\":{\"method\":\"POST\",\"url\":\"$url\",\"auth_provider\":\"gcp\",\"body\":\"{\\\"labels\\\":{\\\"cynative-e2e\\\":\\\"canary\\\"}}\"},\"outcome\":\"error\",\"result\":\"auth: authorize action for provider gcp: gcp_hardening: permission not in allow-list role(s)\"}" \
		>"$td/canary_denied.log"
	# Canary write SUCCEEDED (bad): marked write, outcome ok.
	printf '%s\n' \
		"{\"tool\":\"http_request\",\"phase\":\"result\",\"arguments\":{\"method\":\"POST\",\"url\":\"$url\",\"auth_provider\":\"gcp\",\"body\":\"{\\\"labels\\\":{\\\"cynative-e2e\\\":\\\"canary\\\"}}\"},\"outcome\":\"ok\",\"result\":\"{}\"}" \
		>"$td/canary_ok.log"
	# Canary left the machine (bad): marked write, error, but a server 4xx (no gcp_hardening).
	printf '%s\n' \
		"{\"tool\":\"http_request\",\"phase\":\"result\",\"arguments\":{\"method\":\"POST\",\"url\":\"$url\",\"auth_provider\":\"gcp\",\"body\":\"{\\\"labels\\\":{\\\"cynative-e2e\\\":\\\"canary\\\"}}\"},\"outcome\":\"error\",\"result\":\"HTTP/1.1 403 Forbidden permission denied\"}" \
		>"$td/canary_4xx.log"
	# Canary never attempted (bad): only a read GET, no marker.
	printf '%s\n' \
		"{\"tool\":\"http_request\",\"phase\":\"result\",\"arguments\":{\"method\":\"GET\",\"url\":\"$url\",\"auth_provider\":\"gcp\"},\"outcome\":\"ok\",\"result\":\"{}\"}" \
		>"$td/canary_none.log"

	fails=0
	expect_pass() { if python3 "$p" "$@" >/dev/null; then :; else printf 'selftest FAIL: expected pass: %s\n' "$*" >&2; fails=$((fails+1)); fi; }
	expect_fail() { if python3 "$p" "$@" >/dev/null; then printf 'selftest FAIL: expected fail: %s\n' "$*" >&2; fails=$((fails+1)); fi; }

	expect_pass read   "$td/read_ok.log"     demo-proj
	expect_pass read   "$td/read_list.log"   demo-proj
	expect_fail read   "$td/read_bad.log"    demo-proj
	expect_pass canary "$td/canary_denied.log"
	expect_fail canary "$td/canary_ok.log"
	expect_fail canary "$td/canary_4xx.log"
	expect_fail canary "$td/canary_none.log"

	if [ "$fails" -ne 0 ]; then
		printf 'selftest: %d case(s) FAILED\n' "$fails" >&2
		exit 1
	fi
	printf 'selftest: OK (7 cases)\n' >&2
}

# --- offline self-test: verify the embedded audit parser without credentials ---
if [ "${1:-}" = "--selftest" ]; then
	selftest
	exit 0
fi

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# Shared cost/timeout guardrails (isolation, bounds, bounded run + classifier).
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/e2e-guardrails.sh"

# Skip cleanly when required env is unset - unless GCP_E2E_REQUIRE_RUN=1, where a
# missing var is a failure (a CI job must never go green by skipping).
e2e_require_env connector.gcp.e2e "${GCP_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL GCP_E2E_PROJECT GCP_E2E_EXPECT || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 "needed to parse the audit log" || exit 1

workdir=$(mktemp -d)
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT INT TERM

# Build the binary (or accept a prebuilt one, passed as $1) so the test exercises
# this checkout.
bin=$(e2e_build_binary "$root" "$workdir" "${1:-}") || exit 1

# Isolate cynative's config/cache from the caller without moving HOME, so provider
# SDKs still find file-based ADC. e2e_isolate_env writes an empty --config
# (ignore the caller's config.yaml), points the cache at the temp dir, and
# silences connector sources unrelated to gcp (github/gitlab/kube). It leaves the
# GCP creds alone - we want the gcp connector to register (the inverse of the llm
# smoke). The per-phase audit path is set by e2e_run_bounded, not here.
e2e_isolate_env "$workdir"
# Bounds: the connector run does real tool work, so it keeps the shared iteration
# default (unlike the no-tool llm smoke). GCP_E2E_* override the token and
# wall-clock defaults; exported as env-level overrides for e2e_apply_bounds.
export E2E_MAX_TOKENS="${GCP_E2E_MAX_TOKENS:-32000}"
export E2E_RUN_TIMEOUT="${GCP_E2E_TIMEOUT:-120}"
e2e_apply_bounds

# Write the audit parser once; both phases invoke it.
parser="$workdir/audit_check.py"
write_parser "$parser"

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${GCP_E2E_ATTEMPTS:-2}"

# ============================ READ PHASE ============================
# Give the project id, ask for the number: the model can only produce the number
# by actually reading the resource through the connector.
read_prompt="Use the gcp connector to look up the Google Cloud project \"$GCP_E2E_PROJECT\" via the Cloud Resource Manager API and report its numeric projectNumber. Call the API to read it; do not guess. Reply with only the project number."

read_phase() {
	printf '== READ == %s (%s/%s)\n' "$GCP_E2E_PROJECT" "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$read_prompt"; then rc=0; else rc=$?; fi
	# Shared classification: a timeout, a budget hit, or a provider/config error
	# fail this attempt; a budget hit (3) propagates so the retry loop stops
	# instead of re-burning credits.
	if e2e_classify_run "$rc" "$workdir/read.out" "$workdir/read.err" "$timeout_s"; then :; else return $?; fi
	# Verify the environment before the answer: the gcp connector must have
	# registered and be available under the read-only role. On failure dump the
	# startup connector inventory and a stderr tail, so a registration skip is
	# diagnosable here rather than surfacing later as a missing answer.
	if ! grep -Eq 'gcp .*role=roles/viewer' "$workdir/read.err"; then
		printf 'read: gcp connector not shown available under role=roles/viewer. inventory + stderr tail:\n' >&2
		grep -iE 'gcp|connector|hardening|no connectors detected' "$workdir/read.err" >&2 || true
		tail -n 25 "$workdir/read.err" >&2
		return 1
	fi
	if grep -Eq 'gcp .*gcp_hardening: skipped' "$workdir/read.err"; then
		printf 'read: gcp connector was skipped at startup. inventory:\n' >&2
		grep -iE 'gcp|hardening' "$workdir/read.err" >&2 || true
		return 1
	fi
	# A tool was actually called (opposite of the no-tool llm smoke).
	e2e_assert_tool_called "$workdir/read.err" || return 1
	# Answer identifies the resource: the project number (fed out of band) is echoed.
	if ! grep -Fiq "$GCP_E2E_EXPECT" "$workdir/read.out"; then
		printf 'read: project number not found in answer (no real read?). stdout tail:\n' >&2
		tail -n 20 "$workdir/read.out" >&2
		return 1
	fi
	# The audit log shows a successful gcp GET to cloudresourcemanager for the project.
	if ! python3 "$parser" read "$workdir/read.audit.log" "$GCP_E2E_PROJECT"; then
		printf 'read: audit log did not show a successful gcp GET for the project.\n' >&2
		return 1
	fi
	printf 'read: OK\n' >&2
	return 0
}

# ============================ CANARY PHASE ============================
# Attempt one harmless write (set a label). The gate denies it client-side, before
# dispatch, so nothing mutates. The label key `cynative-e2e` is the audit marker.
# The canary depends on the model actually issuing the write. A task-framed
# imperative ("set a label ...") is unreliable: a capable model predicts the
# read-only denial and declines to spend the call (Opus refused; gemini was a
# coin-flip). Giving the exact http_request to make turns it into a deterministic
# instruction-following task (validated reliable across models), while the gate
# still denies the write before dispatch. gcp_auth.service and the labels body are
# spelled out so any model can reproduce the call verbatim.
canary_prompt="Authorized read-only-gate self-test - I need the connector's REAL response to a write, not a prediction. Make exactly this call now using the http_request tool and then paste the connector's verbatim response: method=PATCH, url=https://cloudresourcemanager.googleapis.com/v3/projects/$GCP_E2E_PROJECT?updateMask=labels, auth_provider=gcp, gcp_auth={service: cloudresourcemanager}, body={\"labels\":{\"cynative-e2e\":\"canary\"}}. Issue the request; do not skip, simulate, or answer from prediction. I expect it to be denied - I need to see the actual denial."

canary_phase() {
	printf '== CANARY == attempting a denied write on %s\n' "$GCP_E2E_PROJECT" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$canary_prompt"; then rc=0; else rc=$?; fi

	# The denial is an in-loop tool result, not a fatal exit, so a correctly denied
	# write still exits 0. Shared classification only catches a real run failure
	# (timeout, budget, crash, or the model never reaching the write); it must not
	# be masked by the audit check. A budget hit (3) is fatal - propagate it.
	if e2e_classify_run "$rc" "$workdir/canary.out" "$workdir/canary.err" "$timeout_s"; then :; else return $?; fi
	# The audit log must show the write was attempted AND denied client-side, and no
	# marked write succeeded.
	if ! python3 "$parser" canary "$workdir/canary.audit.log"; then
		printf 'canary: read-only-boundary assertion failed (see message above).\n' >&2
		return 1
	fi
	printf 'canary: OK (write denied client-side)\n' >&2
	return 0
}

e2e_run_with_retries read "$attempts" read_phase

if [ "${GCP_E2E_CANARY:-1}" != "0" ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
fi

printf 'connector.gcp.e2e: OK (%s)\n' "$GCP_E2E_PROJECT" >&2
