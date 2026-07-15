#!/bin/sh
# llm.smoke.test.sh - live, no-tool LLM smoke test (cynative#38).
#
# Runs the real `cynative -p` one-shot against a real LLM provider selected via
# CYNATIVE_LLM_* env, with a deterministic nonce-echo prompt, and asserts the
# answer round-trips with no tool call. Provider-agnostic: Vertex/Gemini is the
# first caller (cynative#38); Bedrock (cynative#48) reuses this with other env.
#
# NOT hermetic: it talks to a real provider and needs real credentials. Skips
# (exit 0) when no provider is configured, so `make llm-smoke` is a safe no-op.
#
# Usage: sh test/llm.smoke.test.sh [BINARY]
#   BINARY  optional path to a prebuilt cynative binary; default builds from
#           ./cmd/cynative so the smoke exercises this checkout's code.
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (else skip)
#   provider creds (e.g. CYNATIVE_LLM_VERTEX_* / _AUTH_CREDENTIALS for Vertex)
#   SMOKE_TIMEOUT               wall-clock seconds (default 60)
#   SMOKE_MAX_TOKENS            token ceiling (default 16000; a backstop, not a
#                               tight budget - one turn of a thinking model like
#                               gemini-2.5-flash spends a few thousand tokens, and
#                               the budget is checked after the response, so too
#                               low a value discards the answer for a budget notice)
#   SMOKE_REQUIRE_NO_CONNECTORS =1 hard-fails when an AVAILABLE connector
#                               registers (an unavailable "skipped" inventory
#                               line is fine: it cannot serve a request)
#   SMOKE_REQUIRE_RUN          =1 hard-fails (instead of skipping) when provider/
#                               model are unset, so a misconfigured CI job that
#                               would silently skip is caught as a failure
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
	printf 'skip: llm.smoke (set CYNATIVE_LLM_PROVIDER + CYNATIVE_LLM_MODEL + creds to run)\n' >&2
	exit 0
fi

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1

workdir=$(mktemp -d)
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT INT TERM

# Build the binary (or accept a prebuilt one, passed as $1).
bin=$(e2e_build_binary "$root" "$workdir" "${1:-}") || exit 1

# Long, contiguous, no-whitespace nonce that survives markdown reflow.
nonce="SMOKE-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
prompt="Reply with exactly this token and nothing else: $nonce"

# Isolate cynative's config/cache from the caller without moving HOME, so the
# provider SDKs can still find file-based credentials on a local run (~/.aws for
# Bedrock, the gcloud ADC file for Vertex, ~/.azure for Azure). e2e_isolate_env
# writes an empty --config (ignore the caller's ~/.cynative/config.yaml), points
# the cache at the temp dir, and silences connector discovery unrelated to any
# LLM provider (github/gitlab/kube tokens and config-dir overrides). It leaves
# AWS/GCP/Azure creds alone (the LLM provider may need them, e.g. Bedrock), so
# the 0-tool-calls assertion is the real safety net and SMOKE_REQUIRE_NO_CONNECTORS
# is opt-in.
e2e_isolate_env "$workdir"

# Bounds: this is a no-tool smoke, so cap iterations at 1. The public SMOKE_*
# knobs override the shared token/wall-clock defaults; the rest (request timeout,
# subagent iterations, sandbox concurrency) take the shared guardrail defaults.
# Exported as env-level overrides consumed by e2e_apply_bounds.
export E2E_MAX_ITERATIONS=1
export E2E_MAX_TOKENS="${SMOKE_MAX_TOKENS:-16000}"
export E2E_RUN_TIMEOUT="${SMOKE_TIMEOUT:-60}"
e2e_apply_bounds

printf '== RUN == %s/%s\n' "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
if e2e_run_bounded "$E2E_RUN_TIMEOUT" "$workdir/audit.log" "$workdir/out" "$workdir/err" \
	"$bin" "$workdir/config.yaml" "$prompt"; then rc=0; else rc=$?; fi

# Shared classification: a timeout, a budget hit (clear message, not a bogus
# "nonce not found"), or a provider/config/access error. A clean rc 0 falls
# through to the smoke's own assertions below.
e2e_classify_run "$rc" "$workdir/out" "$workdir/err" "$E2E_RUN_TIMEOUT" || exit 1

# Hard: the model echoed the nonce on stdout.
if ! grep -Fq "$nonce" "$workdir/out"; then
	printf 'FAIL: nonce not found in answer (unexpected model response). stdout tail:\n' >&2
	tail -n 20 "$workdir/out" >&2
	exit 1
fi

# Hard: no tool was called (footer on stderr). Anchor the count on a non-digit
# boundary so "0 tool calls" is not matched inside "10 tool calls" etc.
if ! grep -Eq '(^|[^0-9])0 tool calls' "$workdir/err"; then
	printf 'FAIL: expected "0 tool calls" in footer (a tool was called). stderr tail:\n' >&2
	tail -n 20 "$workdir/err" >&2
	exit 1
fi

# Connector check: soft warn by default, hard when SMOKE_REQUIRE_NO_CONNECTORS=1.
# Only an AVAILABLE connector counts as registered: e2e_isolate_env's
# explicit-but-empty KUBECONFIG makes the kubernetes connector print a loud
# "✗ ... skipped" inventory line even on a credential-less CI runner, and an
# unavailable connector cannot serve a request.
if ! e2e_assert_no_available_connectors "$workdir/err"; then
	if [ "${SMOKE_REQUIRE_NO_CONNECTORS:-}" = "1" ]; then
		printf 'FAIL: an available connector registered (SMOKE_REQUIRE_NO_CONNECTORS=1)\n' >&2
		exit 1
	fi
	printf 'warn: an available connector registered (expected none); the 0-tool-calls assertion still holds\n' >&2
fi

printf 'llm.smoke: OK (%s/%s)\n' "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
