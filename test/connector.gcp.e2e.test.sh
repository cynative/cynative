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
# unset, so `make connector-gcp-e2e` is a safe no-op. See
# docs/e2e/live-gcp-connector.md.
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

# Skip cleanly when required env is unset - unless GCP_E2E_REQUIRE_RUN=1, where a
# missing var is a failure (a CI job must never go green by skipping).
missing=
for v in CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL GCP_E2E_PROJECT GCP_E2E_EXPECT; do
	eval "val=\${$v:-}"
	[ -n "$val" ] || missing="$missing $v"
done
if [ -n "$missing" ]; then
	if [ "${GCP_E2E_REQUIRE_RUN:-}" = "1" ]; then
		printf 'FAIL: required env unset but GCP_E2E_REQUIRE_RUN=1:%s\n' "$missing" >&2
		exit 1
	fi
	printf 'skip: connector.gcp.e2e (set CYNATIVE_LLM_* + GCP creds + GCP_E2E_PROJECT/EXPECT to run)\n' >&2
	exit 0
fi

command -v go >/dev/null 2>&1 || { printf 'FAIL: go not found (needed to build cynative)\n' >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { printf 'FAIL: timeout not found\n' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found (needed to parse the audit log)\n' >&2; exit 1; }

workdir=$(mktemp -d)
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT INT TERM

# Build the binary (or accept a prebuilt one) so the test exercises this checkout.
bin=${1:-}
if [ -z "$bin" ]; then
	bin="$workdir/cynative"
	printf '== BUILD ==\n' >&2
	( cd "$root" && go build -o "$bin" ./cmd/cynative ) || { printf 'FAIL: go build failed\n' >&2; exit 1; }
fi
[ -x "$bin" ] || { printf 'FAIL: binary not executable: %s\n' "$bin" >&2; exit 1; }

# Isolate cynative's own config/cache/audit without moving HOME, so provider SDKs
# still find file-based ADC. An empty --config ignores the caller's config.yaml;
# cache/audit go to the temp dir. Silence connector sources unrelated to gcp
# (github/gitlab/kube), but KEEP the GCP creds - we want the gcp connector to
# register (the inverse of the llm smoke).
: > "$workdir/config.yaml"
export CYNATIVE_CACHE_DIR="$workdir/cache"
export CYNATIVE_MAX_TOTAL_TOKENS="${GCP_E2E_MAX_TOKENS:-32000}"
unset GH_CONFIG_DIR GLAB_CONFIG_DIR KUBECONFIG \
	GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN GITLAB_ACCESS_TOKEN OAUTH_TOKEN

# Write the audit parser once; both phases invoke it.
parser="$workdir/audit_check.py"
write_parser "$parser"

timeout_s="${GCP_E2E_TIMEOUT:-120}"
attempts="${GCP_E2E_ATTEMPTS:-2}"

# ============================ READ PHASE ============================
# Give the project id, ask for the number: the model can only produce the number
# by actually reading the resource through the connector.
read_prompt="Use the gcp connector to look up the Google Cloud project \"$GCP_E2E_PROJECT\" via the Cloud Resource Manager API and report its numeric projectNumber. Call the API to read it; do not guess. Reply with only the project number."

read_phase() {
	printf '== READ == %s (%s/%s)\n' "$GCP_E2E_PROJECT" "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	# Truncate the audit log so a retry is evaluated against only this attempt's
	# records (cynative opens the audit log append-only, so a stale record from a
	# failed earlier attempt could otherwise satisfy this attempt's parser).
	: > "$workdir/read.audit.log"
	if CYNATIVE_AUDIT_PATH="$workdir/read.audit.log" \
		timeout "$timeout_s" "$bin" --config "$workdir/config.yaml" -p "$read_prompt" --auto-approve \
		>"$workdir/read.out" 2>"$workdir/read.err" </dev/null; then rc=0; else rc=$?; fi

	if [ "$rc" -eq 124 ]; then
		printf 'read: timed out after %ss\n' "$timeout_s" >&2
		return 1
	fi
	if [ "$rc" -ne 0 ]; then
		printf 'read: run failed (provider/config/access, exit %s). stderr tail:\n' "$rc" >&2
		tail -n 20 "$workdir/read.err" >&2
		return 1
	fi
	# Answer identifies the resource: the project number (fed out of band) is echoed.
	if ! grep -Fiq "$GCP_E2E_EXPECT" "$workdir/read.out"; then
		printf 'read: project number not found in answer (no real read?). stdout tail:\n' >&2
		tail -n 20 "$workdir/read.out" >&2
		return 1
	fi
	# The gcp connector registered and is available under the read-only role.
	if ! grep -Eq 'gcp .*role=roles/viewer' "$workdir/read.err"; then
		printf 'read: gcp connector not shown available under role=roles/viewer. inventory:\n' >&2
		grep -i 'gcp' "$workdir/read.err" >&2 || true
		return 1
	fi
	if grep -Eq 'gcp .*gcp_hardening: skipped' "$workdir/read.err"; then
		printf 'read: gcp connector was skipped at startup. inventory:\n' >&2
		grep -i 'gcp' "$workdir/read.err" >&2 || true
		return 1
	fi
	# A tool was actually called (opposite of the no-tool llm smoke).
	if grep -Eq '(^|[^0-9])0 tool calls' "$workdir/read.err"; then
		printf 'read: footer reports 0 tool calls (no read happened). stderr tail:\n' >&2
		tail -n 20 "$workdir/read.err" >&2
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
	# Truncate first so a retry sees only this attempt's records (see read_phase):
	# a stale marked+denied record from a failed earlier attempt must not satisfy
	# this attempt's parser.
	: > "$workdir/canary.audit.log"
	if CYNATIVE_AUDIT_PATH="$workdir/canary.audit.log" \
		timeout "$timeout_s" "$bin" --config "$workdir/config.yaml" -p "$canary_prompt" --auto-approve \
		>"$workdir/canary.out" 2>"$workdir/canary.err" </dev/null; then crc=0; else crc=$?; fi

	# The denial is an in-loop tool result, not a fatal exit, so a correctly denied
	# write still exits 0. A timeout or any other non-zero exit means the run itself
	# failed (crash, misconfig, or the model never reaching the write) and must not
	# be masked by the audit check - fail, like the read phase.
	if [ "$crc" -eq 124 ]; then
		printf 'canary: timed out after %ss\n' "$timeout_s" >&2
		return 1
	fi
	if [ "$crc" -ne 0 ]; then
		printf 'canary: run failed (exit %s). stderr tail:\n' "$crc" >&2
		tail -n 20 "$workdir/canary.err" >&2
		return 1
	fi
	# The audit log must show the write was attempted AND denied client-side, and no
	# marked write succeeded.
	if ! python3 "$parser" canary "$workdir/canary.audit.log"; then
		printf 'canary: read-only-boundary assertion failed (see message above).\n' >&2
		return 1
	fi
	printf 'canary: OK (write denied client-side)\n' >&2
	return 0
}

# Run each phase, retrying a non-deterministic model miss up to $attempts times.
n=0
while ! read_phase; do
	n=$((n + 1))
	if [ "$n" -ge "$attempts" ]; then
		printf 'FAIL: read phase failed after %d attempt(s)\n' "$n" >&2
		exit 1
	fi
	printf 'retry: read phase attempt %d failed, retrying\n' "$n" >&2
done

if [ "${GCP_E2E_CANARY:-1}" != "0" ]; then
	n=0
	while ! canary_phase; do
		n=$((n + 1))
		if [ "$n" -ge "$attempts" ]; then
			printf 'FAIL: canary phase failed after %d attempt(s)\n' "$n" >&2
			exit 1
		fi
		printf 'retry: canary phase attempt %d failed, retrying\n' "$n" >&2
	done
fi

printf 'connector.gcp.e2e: OK (%s)\n' "$GCP_E2E_PROJECT" >&2
