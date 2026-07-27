#!/bin/sh
# Unit tests for scripts/ci/check-llm-smoke-secrets.sh. Offline and hermetic.
#
# Pins the whitespace-aware secret-boundary tripwire (#216): current workflows
# must pass, and the AGENTS.md-flagged evasions must fail closed.
set -eu
# set -f: fixture bodies may contain glob characters; keep them literal.
set -f

script=scripts/ci/check-llm-smoke-secrets.sh
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

run() {
	# run LABEL expect_exit expect_substr smoke_body release_body
	label=$1
	expect=$2
	substr=$3
	smoke_body=$4
	release_body=$5
	smoke="$tmp/smoke.yaml"
	release="$tmp/release.yaml"
	printf '%s\n' "$smoke_body" >"$smoke"
	printf '%s\n' "$release_body" >"$release"
	set +e
	out=$(sh "$script" "$smoke" "$release" 2>&1)
	got=$?
	set -e
	if [ "$got" -ne "$expect" ]; then
		printf 'FAIL %s (want exit %s, got %s)\n%s\n' "$label" "$expect" "$got" "$out" >&2
		fails=$((fails + 1))
		return
	fi
	if [ -n "$substr" ] && ! printf '%s\n' "$out" | grep -F -q -- "$substr"; then
		printf 'FAIL %s (exit ok but stderr missing %s)\n%s\n' "$label" "$substr" "$out" >&2
		fails=$((fails + 1))
		return
	fi
	printf 'PASS %s\n' "$label"
}

# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
ok_smoke='OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'
# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
ok_release='OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'

run 'current shape passes' 0 '' "$ok_smoke" "$ok_release"

run 'commented bracket form is ignored' 0 '' \
	"$ok_smoke
# decoy: secrets['LEAK']" \
	"$ok_release"

run 'extra secrets.NAME fails' 1 'secrets.* references are' \
	"$ok_smoke
EXTRA: \${{ secrets.APP_PRIVATE_KEY }}" \
	"$ok_release"

run 'adjacent bracket form fails' 1 'bracket-form' \
	"$ok_smoke
LEAK: \${{ secrets[APP_PRIVATE_KEY] }}" \
	"$ok_release"

run 'whitespace before bracket fails' 1 'bracket-form' \
	"$ok_smoke
LEAK: \${{ secrets ['APP_PRIVATE_KEY'] }}" \
	"$ok_release"

run 'double-quoted bracket form fails' 1 'bracket-form' \
	"$ok_smoke
LEAK: \${{ secrets[\"APP_PRIVATE_KEY\"] }}" \
	"$ok_release"

run 'whitespace around dot-form extra secret fails' 1 'secrets.* references are' \
	"$ok_smoke
EXTRA: \${{ secrets . APP_PRIVATE_KEY }}" \
	"$ok_release"

run 'ordinary secrets: inherit fails' 1 "secrets: inherit" \
	"$ok_smoke" \
	"$ok_release
secrets: inherit"

run 'whitespace before colon fails' 1 "secrets: inherit" \
	"$ok_smoke" \
	"$ok_release
secrets : inherit"

run 'quoted inherit value fails' 1 "secrets: inherit" \
	"$ok_smoke" \
	"$ok_release
secrets: \"inherit\""

run 'quoted secrets key fails' 1 "secrets: inherit" \
	"$ok_smoke" \
	"$ok_release
\"secrets\": inherit"

run 'commented secrets: inherit is ignored' 0 '' \
	"$ok_smoke" \
	"$ok_release
# secrets: inherit"

# Folded expression spans join; literal run blocks do not.
run 'multiline bracket form inside expression fails' 1 'bracket-form' \
	"$ok_smoke
LEAK: \${{ secrets
['APP_PRIVATE_KEY'] }}" \
	"$ok_release"

run 'multiline secrets: inherit fails' 1 "secrets: inherit" \
	"$ok_smoke" \
	"$ok_release
secrets
: inherit"

run 'literal run block with secrets then [ is allowed' 0 '' \
	"$ok_smoke
- run: |
    echo secrets
    [ -n \"\$TOKEN\" ] && echo ok" \
	"$ok_release"

run 'quoted hash before bracket leak still fails' 1 'bracket-form' \
	"$ok_smoke
env: { LABEL: \"#\", LEAK: \"\${{ secrets['APP_PRIVATE_KEY'] }}\" }" \
	"$ok_release"

run 'case-insensitive SECRETS. extra fails' 1 'secrets.* references are' \
	"$ok_smoke
EXTRA: \${{ SECRETS.APP_PRIVATE_KEY }}" \
	"$ok_release"

run 'bare secrets context fails' 1 'whole object' \
	"$ok_smoke
ALL: \${{ toJSON(secrets) }}" \
	"$ok_release"

run 'bare secrets expression fails' 1 'whole object' \
	"$ok_smoke
ALL: \${{ secrets }}" \
	"$ok_release"

# YAML workflow_call secrets: keys are not expression context.
run 'yaml secrets key is allowed' 0 '' \
	"$ok_smoke
secrets:
  OPENAI_API_KEY:
    required: true" \
	"$ok_release"

if [ "$fails" -ne 0 ]; then
	printf 'FAIL: %s llm-smoke secret-reference unit test(s) failed\n' "$fails" >&2
	exit 1
fi
printf 'OK: llm-smoke secret-reference unit tests\n'
