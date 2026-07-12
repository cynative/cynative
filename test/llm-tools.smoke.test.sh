#!/bin/sh
# llm-tools.smoke.test.sh - live LLM tool-use smoke test (cynative#49).
#
# Runs the real `cynative -p` one-shot against a real LLM provider selected via
# CYNATIVE_LLM_* env and proves a real model can drive Cynative's tool loop
# through `code_execution`: it is handed a list of random integers and told to
# use the sandbox to compute their exact sum, then answer with only that integer.
#
# Where the no-tool smoke (test/llm.smoke.test.sh, cynative#38) asserts that NO
# tool ran, this one asserts a tool DID run - and specifically code_execution.
# The four checks together catch provider/tool-schema regressions, broken
# tool-call parsing, approval/auto-approve wiring, and sandbox breakage:
#   1. the exact computed sum round-trips into the answer on stdout;
#   2. the stderr footer reports at least one tool call;
#   3. the audit log holds a code_execution result record with outcome "ok" whose
#      output contains the sum - the sandbox ran, the approval gate approved it,
#      and it computed the answer;
#   4. the --verbose per-tool-call notice on stderr names code_execution.
# 3 is the load-bearing proof (machine-readable JSONL, no TTY/render coupling);
# the others are independent cross-checks.
#
# NOT hermetic: it talks to a real provider and needs real credentials. Skips
# (exit 0) when no provider is configured, so `make llm-tools-smoke` is a safe
# no-op. Provider-agnostic: everything is driven by CYNATIVE_LLM_* env.
#
# Usage: sh test/llm-tools.smoke.test.sh [BINARY]
#   BINARY  optional path to a prebuilt cynative binary; default builds from
#           ./cmd/cynative so the smoke exercises this checkout's code.
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (else skip)
#   provider creds (e.g. AWS creds for Bedrock, a Vertex service account for
#                   Vertex)
#   SMOKE_TIMEOUT        wall-clock seconds (default 90)
#   SMOKE_MAX_TOKENS     token ceiling (default 40000; a backstop, not a tight
#                        budget - a tool turn is two model calls plus the echoed
#                        script, so the no-tool script's 16000 default is too low
#                        here and would discard the answer for a budget notice)
#   SMOKE_MAX_ITERATIONS agent-loop bound (default 6; tool use needs at least 2:
#                        one turn to call the tool, one to answer)
#   SMOKE_REQUIRE_RUN    =1 hard-fails (instead of skipping) when provider/model
#                        are unset, so a misconfigured CI job cannot go green by
#                        silently skipping
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# Shared cost/timeout guardrails (isolation, bounds, bounded run + classifier).
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/e2e-guardrails.sh"

# Skip cleanly when no provider is configured - unless SMOKE_REQUIRE_RUN=1, where
# a missing provider/model is a failure (a CI job must never go green by skipping).
if [ -z "${CYNATIVE_LLM_PROVIDER:-}" ] || [ -z "${CYNATIVE_LLM_MODEL:-}" ]; then
	if [ "${SMOKE_REQUIRE_RUN:-}" = "1" ]; then
		printf 'FAIL: CYNATIVE_LLM_PROVIDER/CYNATIVE_LLM_MODEL unset but SMOKE_REQUIRE_RUN=1\n' >&2
		exit 1
	fi
	printf 'skip: llm-tools.smoke (set CYNATIVE_LLM_PROVIDER + CYNATIVE_LLM_MODEL + creds to run)\n' >&2
	exit 0
fi

e2e_require_cmd timeout || exit 1
# python3 parses the audit log below (the load-bearing tool-use check); the repo's
# other live e2e tests take the same dependency.
e2e_require_cmd python3 "needed to parse the audit log" || exit 1

workdir=$(mktemp -d)
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT INT TERM

# Build the binary (or accept a prebuilt one, passed as $1). go is only needed
# when building; e2e_build_binary presence-checks it in that branch.
bin=$(e2e_build_binary "$root" "$workdir" "${1:-}") || exit 1

# A deterministic, tool-shaped task: sum 40 random 16-bit integers. The model
# cannot reliably do this in its head, and the tool's own description reserves
# code_execution for "non-trivial or precision-sensitive math", so a genuine sum
# steers it to the sandbox; the explicit instruction makes that a requirement.
# 40 * 65535 = 2,621,400, so the sum stays a small exact integer (no overflow in
# the shell accumulator below or in the sandbox's float64).
nums=$(od -An -N80 -tu2 /dev/urandom | tr -s ' ' '\n' | grep -E '^[0-9]+$' | head -n 40)
count=$(printf '%s\n' "$nums" | grep -c .)
if [ "$count" -ne 40 ]; then
	printf 'FAIL: expected 40 random integers, generated %s (od/urandom problem)\n' "$count" >&2
	exit 1
fi
list=$(printf '%s' "$nums" | paste -sd, -)
sum=0
for n in $nums; do sum=$((sum + n)); done

prompt="You must use the code_execution tool to compute this; do not compute it \
yourself. Compute the exact integer sum of the following numbers and reply with \
only that integer and nothing else: $list"

# Isolate cynative's config/cache from the caller without moving HOME, so the
# provider SDKs can still find file-based credentials on a local run (~/.aws for
# Bedrock, the gcloud ADC file for Vertex). e2e_isolate_env writes an empty
# --config, points the cache at the temp dir, and silences connector discovery
# unrelated to any LLM provider; ambient cloud creds may still register the
# aws/gcp/azure connectors on a cloud host, which is fine - this test asserts a
# code_execution call, not the connector set. The audit log is asserted below, so
# enable it and route it into the temp dir.
e2e_isolate_env "$workdir"
export CYNATIVE_AUDIT_ENABLED=true

# Bounds: tool use needs a few iterations (at least 2 - call the tool, then
# answer), a larger token budget than the no-tool smoke (a tool turn is two model
# calls plus the echoed script), and a longer wall-clock. The public SMOKE_* knobs
# override the shared defaults; the rest take the guardrail defaults.
export E2E_MAX_ITERATIONS="${SMOKE_MAX_ITERATIONS:-6}"
export E2E_MAX_TOKENS="${SMOKE_MAX_TOKENS:-40000}"
export E2E_RUN_TIMEOUT="${SMOKE_TIMEOUT:-90}"
e2e_apply_bounds

printf '== RUN == %s/%s (sum of %s integers)\n' "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" "$count" >&2
# --verbose is passed through so check 4 can see the per-tool-call notice.
if e2e_run_bounded "$E2E_RUN_TIMEOUT" "$workdir/audit.log" "$workdir/out" "$workdir/err" \
	"$bin" "$workdir/config.yaml" "$prompt" --verbose; then rc=0; else rc=$?; fi

# Shared classification: a timeout, a budget hit (clear message, not a bogus
# "sum not found"), or a provider/config/access error. A clean rc 0 falls through
# to the tool-use assertions below.
e2e_classify_run "$rc" "$workdir/out" "$workdir/err" "$E2E_RUN_TIMEOUT" || exit 1

# 1. The exact computed sum round-tripped into the answer on stdout. Drop thousands
# separators, then require some run of digits to equal the sum exactly (grep -Fx),
# so the value is neither missed when a model groups digits (1,401,486) nor matched
# inside a longer number.
if ! tr -d ',' < "$workdir/out" | grep -oE '[0-9]+' | grep -Fxq "$sum"; then
	printf 'FAIL: expected sum %s not found in answer. stdout tail:\n' "$sum" >&2
	tail -n 20 "$workdir/out" >&2
	exit 1
fi

# 2. The footer (always stderr) reports at least one tool call. A positive match
# (not "not 0") also fails a missing or reshaped footer.
if ! grep -Eq '(^|[^0-9])[1-9][0-9]* tool call' "$workdir/err"; then
	printf 'FAIL: expected at least one tool call in the footer. stderr tail:\n' >&2
	tail -n 20 "$workdir/err" >&2
	exit 1
fi

# 3. Load-bearing proof: the audit log holds a code_execution RESULT record whose
# outcome is "ok" AND whose result (the sandbox's own output) contains the sum -
# so the sandbox actually executed, the approval gate approved it, and it computed
# the answer (not the model in its head with an unrelated tool call on the side).
# Parse the outer JSON fields with python3: substring greps would be fooled by the
# model-controlled arguments object, which serializes unescaped into the record.
if ! python3 - "$sum" "$workdir/audit.log" <<'PY'
import json, re, sys

want = sys.argv[1]
digit_bounded = re.compile(r"(?<!\d)" + re.escape(want) + r"(?!\d)")
found = False
try:
    with open(sys.argv[2]) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("tool") != "code_execution":
                continue
            if rec.get("phase") != "result" or rec.get("outcome") != "ok":
                continue
            result = rec.get("result")
            # Strip thousands separators so a toLocaleString-style print still matches.
            if isinstance(result, str) and digit_bounded.search(result.replace(",", "")):
                found = True
                break
except OSError:
    found = False
sys.exit(0 if found else 1)
PY
then
	printf 'FAIL: no successful code_execution result computing the sum in the audit log. audit tail:\n' >&2
	tail -n 20 "$workdir/audit.log" 2>/dev/null >&2 || printf '(no audit log)\n' >&2
	exit 1
fi

# 4. Cross-check on the human-visible path: the --verbose per-tool-call notice on
# stderr names code_execution. render.go writes "\n<glyph> <tool> <args>\n", so
# this matches the notice, not the "Tool Call:" approval preview (which is
# TTY-routed and may not reach stderr).
if ! grep -Fq '🔧 code_execution' "$workdir/err"; then
	printf 'FAIL: no verbose code_execution notice on stderr. stderr tail:\n' >&2
	tail -n 20 "$workdir/err" >&2
	exit 1
fi

printf 'llm-tools.smoke: OK (%s/%s, code_execution summed %s integers to %s)\n' \
	"$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" "$count" "$sum" >&2
