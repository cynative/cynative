#!/bin/sh
# check-llm-smoke-secrets.sh - pin the llm-smoke / release secret boundary.
#
# The api-key legs read exactly two secrets across the workflow_call boundary.
# release.yaml forwards ONLY these two names, never secrets: inherit. Pin the
# boundary from both sides:
#   llm-smoke.yaml - the sorted-unique set of secrets.<NAME> refs must be exactly
#     the two keys; bracket-form secrets[...] and bare secrets-context accesses
#     (e.g. toJSON(secrets)) are rejected;
#   release.yaml - secrets: inherit (quoted or unquoted) must never appear.
#
# Whitespace around the context identifier / `.` / `[` is allowed so folded YAML
# expressions cannot slip past. Newlines are joined only inside `${{ ... }}`
# spans, so a literal `run: |` block that ends one line with `secrets` and starts
# the next with `[` is not a false positive. Comment stripping is quote-aware so
# a `#` inside a quoted scalar is not treated as a YAML comment opener.
#
# This is still a tripwire, not a YAML/Actions expression parser: exotic forms
# may remain. See AGENTS.md.
#
# Usage: sh scripts/ci/check-llm-smoke-secrets.sh [llm-smoke.yaml] [release.yaml]
set -eu
# set -f: nothing here wants globbing; keep glob characters in paths and names literal.
set -f

smoke_file=${1:-.github/workflows/llm-smoke.yaml}
release_file=${2:-.github/workflows/release.yaml}

if [ ! -f "$smoke_file" ]; then
	printf 'FAIL: llm-smoke workflow not found: %s\n' "$smoke_file" >&2
	exit 1
fi
if [ ! -r "$smoke_file" ]; then
	printf 'FAIL: llm-smoke workflow not readable: %s\n' "$smoke_file" >&2
	exit 1
fi
if [ ! -f "$release_file" ]; then
	printf 'FAIL: release workflow not found: %s\n' "$release_file" >&2
	exit 1
fi
if [ ! -r "$release_file" ]; then
	printf 'FAIL: release workflow not readable: %s\n' "$release_file" >&2
	exit 1
fi

# Quote-aware comment strip, then join newlines only while inside an open
# `${{ ... }}` expression (Actions folds those; literal blocks keep newlines).
normalize() {
	awk '
	function strip_comment(s,   in_dq, in_sq, i, c, out) {
		in_dq = 0
		in_sq = 0
		out = ""
		for (i = 1; i <= length(s); i++) {
			c = substr(s, i, 1)
			if (c == "\"" && !in_sq) { in_dq = !in_dq; out = out c; continue }
			if (c == "'\''" && !in_dq) { in_sq = !in_sq; out = out c; continue }
			if (c == "#" && !in_dq && !in_sq) break
			out = out c
		}
		return out
	}
	function update_depth(s,   tok) {
		while (match(s, /\$\{\{|}}/)) {
			tok = substr(s, RSTART, RLENGTH)
			if (tok == "${{") depth++
			else if (depth > 0) depth--
			s = substr(s, RSTART + RLENGTH)
		}
	}
	{
		line = strip_comment($0)
		if (depth == 0) {
			if (have) print out
			out = line
			have = 1
		} else {
			out = out " " line
		}
		update_depth(line)
	}
	END { if (have) print out }
	' "$1"
}

smoke=$(normalize "$smoke_file")
release=$(normalize "$release_file")

# Case-insensitive secrets context; Actions resolves context ids that way.
smoke_lc=$(printf '%s\n' "$smoke" | tr '[:upper:]' '[:lower:]')
release_lc=$(printf '%s\n' "$release" | tr '[:upper:]' '[:lower:]')

# Bracket-form: secrets[ / secrets [ / Secrets["K"]
if printf '%s\n' "$smoke_lc" | grep -qE 'secrets[[:space:]]*\['; then
	printf 'FAIL: %s uses bracket-form secrets[...]; only dot-form secrets.NAME is allowed so this pin can enforce the exact set.\n' \
		"$smoke_file" >&2
	exit 1
fi

# Dot-form with optional whitespace around the dot. Context match is
# case-insensitive; secret names stay case-sensitive against the allow-list.
got=$(printf '%s\n' "$smoke" | grep -oiE 'secrets[[:space:]]*\.[[:space:]]*[A-Za-z0-9_]+' |
	sed -E 's/^[Ss][Ee][Cc][Rr][Ee][Tt][Ss][[:space:]]*\.[[:space:]]*//' | sort -u)
want=$(printf '%s\n' 'ANTHROPIC_API_KEY' 'OPENAI_API_KEY')
if [ "$got" != "$want" ]; then
	printf 'FAIL: %s secrets.* references are [%s], expected exactly [%s] - a new reference would widen the gate'\''s secret access across workflow_call.\n' \
		"$smoke_file" "$(printf '%s' "$got" | tr '\n' ' ')" "$(printf '%s' "$want" | tr '\n' ' ')" >&2
	exit 1
fi

# Whole-object secrets context inside `${{ ... }}` only (toJSON(secrets),
# `${{ secrets }}`). YAML `secrets:` keys and literal `echo secrets` must pass.
# Named forms are scrubbed first; anything left is a bare context access.
if printf '%s\n' "$smoke_lc" | grep -oE '\$\{\{[^}]*\}\}' | sed -E \
	's/secrets[[:space:]]*\.[[:space:]]*[a-z0-9_]+//g; s/secrets[[:space:]]*\[[^]]*\]//g' |
	grep -qE '(^|[^a-z0-9_])secrets([^a-z0-9_]|$)'; then
	printf 'FAIL: %s references the secrets context as a whole object; only the two named secrets.NAME keys are allowed.\n' \
		"$smoke_file" >&2
	exit 1
fi

# secrets: inherit / "secrets": "inherit" / secrets : inherit (optional quotes/whitespace)
inherit_re='["'\'']?secrets["'\'']?[[:space:]]*:[[:space:]]*["'\'']?inherit["'\'']?'
if printf '%s\n' "$release_lc" | grep -qE "$inherit_re"; then
	printf 'FAIL: %s uses '\''secrets: inherit'\'' - reusable gates must be granted only the exact named secrets they need, never the full set.\n' \
		"$release_file" >&2
	exit 1
fi
# Same key split across physical lines outside ${{ }} (normalize does not join those).
if printf '%s\n' "$release_lc" | awk '
	{
		if (prev ~ /["'\'']?secrets["'\'']?[[:space:]]*$/ && $0 ~ /^[[:space:]]*:[[:space:]]*["'\'']?inherit["'\'']?/) {
			found = 1
			exit
		}
		prev = $0
	}
	END { exit found ? 0 : 1 }
'; then
	printf 'FAIL: %s uses '\''secrets: inherit'\'' - reusable gates must be granted only the exact named secrets they need, never the full set.\n' \
		"$release_file" >&2
	exit 1
fi

exit 0
