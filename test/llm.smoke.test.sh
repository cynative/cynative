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
#   SMOKE_REQUIRE_NO_CONNECTORS =1 hard-fails unless no connector registers
#   SMOKE_REQUIRE_RUN          =1 hard-fails (instead of skipping) when provider/
#                               model are unset, so a misconfigured CI job that
#                               would silently skip is caught as a failure
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)

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

command -v go >/dev/null 2>&1 || { printf 'FAIL: go not found (needed to build cynative)\n' >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { printf 'FAIL: timeout not found\n' >&2; exit 1; }

workdir=$(mktemp -d)
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT INT TERM

# Build the binary (or accept a prebuilt one).
bin=${1:-}
if [ -z "$bin" ]; then
	bin="$workdir/cynative"
	printf '== BUILD ==\n' >&2
	( cd "$root" && go build -o "$bin" ./cmd/cynative ) || { printf 'FAIL: go build failed\n' >&2; exit 1; }
fi
[ -x "$bin" ] || { printf 'FAIL: binary not executable: %s\n' "$bin" >&2; exit 1; }

# Long, contiguous, no-whitespace nonce that survives markdown reflow.
nonce="SMOKE-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
prompt="Reply with exactly this token and nothing else: $nonce"

# Isolate cynative's OWN config/cache/audit without moving HOME, so the provider
# SDKs can still find file-based credentials on a local run (~/.aws for Bedrock,
# the gcloud ADC file for Vertex, ~/.azure for Azure). An empty --config makes
# cynative ignore the caller's ~/.cynative/config.yaml, and cache/audit go to the
# temp dir. Silence connector discovery sources unrelated to any LLM provider
# (github/gitlab/kube tokens and config-dir overrides are never LLM creds). Do
# NOT unset AWS/GCP/Azure creds: the LLM provider may need them (e.g. Bedrock uses
# AWS creds), so the aws/gcp connectors can still register on a cloud host - the
# 0-tool-calls assertion is the real safety net, and SMOKE_REQUIRE_NO_CONNECTORS
# is opt-in (CI only, where the runner is clean).
: > "$workdir/config.yaml"
export CYNATIVE_CACHE_DIR="$workdir/cache"
export CYNATIVE_AUDIT_PATH="$workdir/audit.log"
unset GH_CONFIG_DIR GLAB_CONFIG_DIR KUBECONFIG \
	GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN GITLAB_ACCESS_TOKEN OAUTH_TOKEN

printf '== RUN == %s/%s\n' "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
# timeout returns non-zero on a slow/failed run, which under `set -e` would abort
# before rc is captured, so wrap it (house pattern, test/install.e2e.test.sh).
set +e
CYNATIVE_MAX_ITERATIONS=1 CYNATIVE_MAX_TOTAL_TOKENS="${SMOKE_MAX_TOKENS:-16000}" \
	timeout "${SMOKE_TIMEOUT:-60}" "$bin" --config "$workdir/config.yaml" -p "$prompt" --auto-approve \
		>"$workdir/out" 2>"$workdir/err" </dev/null
rc=$?
set -e

# Failure classification.
if [ "$rc" -eq 124 ]; then
	printf 'FAIL: timed out after %ss\n' "${SMOKE_TIMEOUT:-60}" >&2
	exit 1
fi
if [ "$rc" -ne 0 ]; then
	printf 'FAIL: provider/config/access (exit %s). stderr tail:\n' "$rc" >&2
	tail -n 20 "$workdir/err" >&2
	exit 1
fi

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
if ! grep -Fq '(no connectors detected)' "$workdir/err"; then
	if [ "${SMOKE_REQUIRE_NO_CONNECTORS:-}" = "1" ]; then
		printf 'FAIL: a connector registered (SMOKE_REQUIRE_NO_CONNECTORS=1)\n' >&2
		exit 1
	fi
	printf 'warn: a connector registered (expected none); the 0-tool-calls assertion still holds\n' >&2
fi

printf 'llm.smoke: OK (%s/%s)\n' "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
