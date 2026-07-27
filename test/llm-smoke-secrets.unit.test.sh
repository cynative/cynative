#!/bin/sh
# Unit tests for scripts/ci/check-llm-smoke-secrets.sh. Offline and hermetic.
#
# Pins the whitespace-aware secret-boundary tripwire (#216): current workflows
# must pass, and the AGENTS.md-flagged evasions (secrets ['K'], secrets : inherit)
# must fail closed.
set -eu

script=scripts/ci/check-llm-smoke-secrets.sh
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

run() {
	# run LABEL expect_exit smoke_body release_body
	label=$1
	expect=$2
	smoke_body=$3
	release_body=$4
	smoke="$tmp/smoke.yaml"
	release="$tmp/release.yaml"
	printf '%s\n' "$smoke_body" >"$smoke"
	printf '%s\n' "$release_body" >"$release"
	set +e
	out=$(sh "$script" "$smoke" "$release" 2>&1)
	got=$?
	set -e
	if [ "$got" -eq "$expect" ]; then
		printf 'PASS %s\n' "$label"
	else
		printf 'FAIL %s (want exit %s, got %s)\n%s\n' "$label" "$expect" "$got" "$out" >&2
		fails=$((fails + 1))
	fi
}

ok_smoke='OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'
ok_release='OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'

run 'current shape passes' 0 "$ok_smoke" "$ok_release"

run 'commented bracket form is ignored' 0 \
	"$ok_smoke
# decoy: secrets['LEAK']" \
	"$ok_release"

run 'extra secrets.NAME fails' 1 \
	"$ok_smoke
EXTRA: \${{ secrets.APP_PRIVATE_KEY }}" \
	"$ok_release"

run 'adjacent bracket form fails' 1 \
	"$ok_smoke
LEAK: \${{ secrets[APP_PRIVATE_KEY] }}" \
	"$ok_release"

run 'whitespace before bracket fails (AGENTS evasion)' 1 \
	"$ok_smoke
LEAK: \${{ secrets ['APP_PRIVATE_KEY'] }}" \
	"$ok_release"

run 'double-quoted bracket form fails' 1 \
	"$ok_smoke
LEAK: \${{ secrets[\"APP_PRIVATE_KEY\"] }}" \
	"$ok_release"

run 'ordinary secrets: inherit fails' 1 \
	"$ok_smoke" \
	"$ok_release
secrets: inherit"

run 'whitespace before colon fails (AGENTS evasion)' 1 \
	"$ok_smoke" \
	"$ok_release
secrets : inherit"

run 'commented secrets: inherit is ignored' 0 \
	"$ok_smoke" \
	"$ok_release
# secrets: inherit"

# Folded / multiline YAML: Actions joins the expression with whitespace, so the
# tripwire must see across physical lines after normalize (Codex #218 review).
run 'multiline bracket form fails' 1 \
	"$ok_smoke
LEAK: \${{ secrets
['APP_PRIVATE_KEY'] }}" \
	"$ok_release"

run 'multiline secrets: inherit fails' 1 \
	"$ok_smoke" \
	"$ok_release
secrets
: inherit"

# Live workflows under the repo root must still pass the checker.
set +e
live_out=$(sh "$script" 2>&1)
live=$?
set -e
if [ "$live" -eq 0 ]; then
	printf 'PASS live llm-smoke.yaml + release.yaml\n'
else
	printf 'FAIL live workflows (want exit 0, got %s)\n%s\n' "$live" "$live_out" >&2
	fails=$((fails + 1))
fi

if [ "$fails" -ne 0 ]; then
	printf 'FAIL: %s llm-smoke secret-reference unit test(s) failed\n' "$fails" >&2
	exit 1
fi
printf 'OK: llm-smoke secret-reference unit tests\n'
