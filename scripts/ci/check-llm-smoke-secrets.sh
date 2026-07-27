#!/bin/sh
# check-llm-smoke-secrets.sh - pin the llm-smoke / release secret boundary.
#
# The api-key legs read exactly two secrets across the workflow_call boundary.
# release.yaml forwards ONLY these two names, never secrets: inherit. Pin the
# boundary from both sides, comments stripped (sed 's/#.*//') so prose never counts:
#   llm-smoke.yaml - the sorted-unique set of secrets.<NAME> refs must be exactly
#     the two keys, and bracket-form secrets[...] is rejected outright since it
#     would evade the dot-form scan;
#   release.yaml - `secrets: inherit` must never appear, or a future edit could
#     hand every release secret (App key, signing, PAT) to the gate.
#
# Patterns intentionally allow optional whitespace so YAML/GitHub forms like
# `secrets ['K']` and `secrets : inherit` cannot slip past (AGENTS.md / #216).
#
# Usage: sh scripts/ci/check-llm-smoke-secrets.sh [llm-smoke.yaml] [release.yaml]
set -eu

smoke_file=${1:-.github/workflows/llm-smoke.yaml}
release_file=${2:-.github/workflows/release.yaml}

if [ ! -f "$smoke_file" ]; then
	printf 'FAIL: llm-smoke workflow not found: %s\n' "$smoke_file" >&2
	exit 1
fi
if [ ! -f "$release_file" ]; then
	printf 'FAIL: release workflow not found: %s\n' "$release_file" >&2
	exit 1
fi

smoke=$(sed 's/#.*//' "$smoke_file")
# Bracket-form (with optional whitespace): secrets[ / secrets [ / secrets["K"]
if printf '%s\n' "$smoke" | grep -qE 'secrets[[:space:]]*\['; then
	printf 'FAIL: %s uses bracket-form secrets[...]; only dot-form secrets.NAME is allowed so this pin can enforce the exact set.\n' \
		"$smoke_file" >&2
	exit 1
fi

got=$(printf '%s\n' "$smoke" | grep -oE 'secrets\.[A-Za-z0-9_]+' | sed 's/^secrets\.//' | sort -u | tr '\n' ' ')
got=$(printf '%s' "$got" | sed 's/[[:space:]]*$//')
want="ANTHROPIC_API_KEY OPENAI_API_KEY"
if [ "$got" != "$want" ]; then
	printf 'FAIL: %s secrets.* references are [%s], expected exactly [%s] - a new reference would widen the gate'\''s secret access across workflow_call.\n' \
		"$smoke_file" "$got" "$want" >&2
	exit 1
fi

# secrets: inherit / secrets : inherit (optional whitespace around ':')
if sed 's/#.*//' "$release_file" | grep -qE 'secrets[[:space:]]*:[[:space:]]*inherit'; then
	printf 'FAIL: %s uses '\''secrets: inherit'\'' - reusable gates must be granted only the exact named secrets they need, never the full set.\n' \
		"$release_file" >&2
	exit 1
fi

exit 0
