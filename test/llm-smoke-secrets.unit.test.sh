#!/bin/sh
# Unit tests for scripts/ci/check-llm-smoke-secrets.py. Offline and hermetic.
#
# Pins the secret-boundary tripwire (cynative#216): the current workflow shape must
# pass, every widening spelling must fail closed, and the prose/comment shapes this
# repo actually writes must not misfire.
#
# Every fixture is asserted to be parseable YAML before it is used. That guard is
# load-bearing: an earlier revision of this suite pinned `secrets` NEWLINE `: inherit`,
# which no YAML parser accepts, so the case proved nothing about a reachable evasion
# while the two spellings that DO parse both passed the checker.
set -eu
# set -f: fixture bodies may contain glob characters; keep them literal.
set -f

script=scripts/ci/check-llm-smoke-secrets.py
fails=0
ran=0

command -v python3 >/dev/null 2>&1 || {
	printf 'FAIL: python3 not found (required by %s)\n' "$script" >&2
	exit 1
}
python3 -c 'import yaml' 2>/dev/null || {
	printf 'FAIL: PyYAML not found (required by %s); apt: python3-yaml, pip: PyYAML\n' "$script" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# A minimal but structurally faithful pair: the gate names its two keys, the caller
# forwards exactly those two across the workflow_call boundary.
# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
ok_smoke='on:
  workflow_call:
    secrets:
      OPENAI_API_KEY:
        required: true
      ANTHROPIC_API_KEY:
        required: true
jobs:
  leg:
    runs-on: ubuntu-latest
    steps:
      - name: smoke
        run: make llm-smoke
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'
# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
ok_release='jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'

# run_raw LABEL expect_exit expect_substr smoke_path release_path
run_raw() {
	label=$1
	expect=$2
	substr=$3
	set +e
	out=$(python3 -B "$script" "$4" "$5" 2>&1)
	got=$?
	set -e
	if [ "$got" -ne "$expect" ]; then
		printf 'FAIL %s (want exit %s, got %s)\n%s\n' "$label" "$expect" "$got" "$out" >&2
		fails=$((fails + 1))
		return
	fi
	if [ -n "$substr" ] && ! printf '%s\n' "$out" | grep -F -q -- "$substr"; then
		printf 'FAIL %s (exit ok but message missing %s)\n%s\n' "$label" "$substr" "$out" >&2
		fails=$((fails + 1))
		return
	fi
	printf 'PASS %s\n' "$label"
}

# run LABEL expect_exit expect_substr smoke_body release_body
run() {
	label=$1
	expect=$2
	substr=$3
	smoke_body=$4
	release_body=$5
	ran=$((ran + 1))
	# The basename matters: check_forwarding finds the gate call in release.yaml by
	# matching the `uses:` target against this file's name.
	smoke="$tmp/llm-smoke.yaml"
	release="$tmp/release.yaml"
	printf '%s\n' "$smoke_body" >"$smoke"
	printf '%s\n' "$release_body" >"$release"
	# Every fixture must be real YAML, or the case proves nothing. The deliberate
	# fail-closed-on-unparseable cases call run_raw directly instead.
	if ! python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$smoke" 2>/dev/null ||
		! python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$release" 2>/dev/null; then
		printf 'FAIL %s (fixture is not parseable YAML, so the case is vacuous)\n' "$label" >&2
		fails=$((fails + 1))
		return
	fi
	run_raw "$label" "$expect" "$substr" "$smoke" "$release"
}

run 'current shape passes' 0 '' "$ok_smoke" "$ok_release"

# --- the exact-set assertion on llm-smoke.yaml -------------------------------
run 'extra secrets.NAME fails' 1 'secrets.* references are' \
	"$ok_smoke
          EXTRA: \${{ secrets.APP_PRIVATE_KEY }}" \
	"$ok_release"

# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
run 'a missing required key fails' 1 'secrets.* references are' \
	'jobs:
  leg:
    steps:
      - env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}' \
	"$ok_release"

run 'whitespace around the dot still resolves the name' 1 'secrets.* references are' \
	"$ok_smoke
          EXTRA: \${{ secrets . APP_PRIVATE_KEY }}" \
	"$ok_release"

run 'case-folded SECRETS. is the same context' 1 'secrets.* references are' \
	"$ok_smoke
          EXTRA: \${{ SECRETS.APP_PRIVATE_KEY }}" \
	"$ok_release"

# --- bracket form, both sides ------------------------------------------------
run 'bracket form in llm-smoke fails' 1 'bracket-form' \
	"$ok_smoke
          LEAK: \${{ secrets['APP_PRIVATE_KEY'] }}" \
	"$ok_release"

run 'whitespace before the bracket fails' 1 'bracket-form' \
	"$ok_smoke
          LEAK: \${{ secrets ['APP_PRIVATE_KEY'] }}" \
	"$ok_release"

run 'double-quoted bracket form fails' 1 'bracket-form' \
	"$ok_smoke
          LEAK: \${{ secrets[\"APP_PRIVATE_KEY\"] }}" \
	"$ok_release"

# release.yaml is the side that forwards secrets, so it needs the same arms.
run 'bracket form in release fails' 1 'bracket-form' \
	"$ok_smoke" \
	"$ok_release
      LEAK: \${{ secrets['APP_PRIVATE_KEY'] }}"

# --- whole-object access, both sides ----------------------------------------
run 'toJSON(secrets) fails' 1 'whole object' \
	"$ok_smoke
          ALL: \${{ toJSON(secrets) }}" \
	"$ok_release"

run 'bare secrets expression fails' 1 'whole object' \
	"$ok_smoke
          ALL: \${{ secrets }}" \
	"$ok_release"

# A `}` inside a string literal must not end the expression span early, or the
# whole-object arm would scan nothing and pass vacuously.
run 'toJSON(secrets) wrapped in format() fails' 1 'whole object' \
	"$ok_smoke
          ALL: \${{ format('{0}', toJSON(secrets)) }}" \
	"$ok_release"

run 'whole-object forward in release fails' 1 'whole object' \
	"$ok_smoke" \
	"$ok_release
      OPENAI_API_KEY: \${{ toJSON(secrets) }}"

# --- secrets: inherit, every spelling that parses to the same node -----------
run 'one-line secrets: inherit fails' 1 'secrets: inherit' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets: inherit'

run 'inherit on the following line fails' 1 'secrets: inherit' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets:
      inherit'

run 'folded inherit fails' 1 'secrets: inherit' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets: >-
      inherit'

run 'quoted inherit fails' 1 'secrets: inherit' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets: "inherit"'

run 'tagged !!str inherit fails' 1 'secrets: inherit' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets: !!str inherit'

run 'aliased inherit fails' 1 'secrets: inherit' \
	"$ok_smoke" \
	'grant: &grant inherit
jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets: *grant'

run 'inherit in llm-smoke fails too' 1 'secrets: inherit' \
	"$ok_smoke
  nested:
    uses: ./other.yaml
    secrets: inherit" \
	"$ok_release"

# --- comments and prose carry no meaning -------------------------------------
# The parser drops comments, so neither of these can hide or invent a reference.
run 'commented bracket form is ignored' 0 '' \
	"$ok_smoke
          # decoy: \${{ secrets['LEAK'] }}" \
	"$ok_release"

run 'commented secrets: inherit is ignored' 0 '' \
	"$ok_smoke" \
	"$ok_release
    # never use secrets: inherit here"

# An apostrophe earlier on the line used to desync a quote-tracking comment
# stripper and make the trailing comment count as live YAML. release.yaml really
# does carry a comment naming this phrase, so the misfire was reachable.
run "apostrophe before an inline comment is still a comment" 0 '' \
	"$ok_smoke" \
	"$ok_release
    # the gate's grant is narrow: never secrets: inherit"

# A `#` inside a block scalar is shell, not a YAML comment: the rest of the line
# must stay visible, so a reference after it is still counted.
run 'hash in a run block does not hide a later reference' 1 'secrets.* references are' \
	"$ok_smoke
        shell: bash
        script: echo \${MODEL#us.} \${{ secrets.APP_PRIVATE_KEY }}" \
	"$ok_release"

run 'shell comment in a run block does not hide a reference' 1 'secrets.* references are' \
	"$ok_smoke
        script: |
          curl -s \"\$URL\" # fetch \${{ secrets.APP_PRIVATE_KEY }}" \
	"$ok_release"

run 'the word secrets in prose is not a reference' 0 '' \
	"$ok_smoke
        summary: audit the gate's secrets [all of them] and secrets. done" \
	"$ok_release"

run 'a literal run block with secrets then a bracket is allowed' 0 '' \
	"$ok_smoke
        script: |
          echo secrets
          [ -n \"\$TOKEN\" ] && echo ok" \
	"$ok_release"

# --- other contexts that merely end in .secrets ------------------------------
run 'inputs.secrets is a different context' 0 '' \
	"$ok_smoke
          OTHER: \${{ inputs.secrets }}" \
	"$ok_release"

run 'needs outputs ending in secrets is a different context' 0 '' \
	"$ok_smoke
          OTHER: \${{ needs.build.outputs.secrets }}" \
	"$ok_release"

run 'the word secrets inside a string literal is not a context' 0 '' \
	"$ok_smoke
          OTHER: \${{ format('secrets', inputs.a) }}" \
	"$ok_release"

# --- what release.yaml may hand the gate -------------------------------------
# The exact-set arm counts references INSIDE llm-smoke.yaml, so on its own it is
# satisfied by a caller that forwards a real secret under an allow-listed name:
# the gate's own text never changes. These pin the forwarding itself.
# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
run 'forwarding a secret under an allow-listed name fails' 1 'under a different name' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets:
      OPENAI_API_KEY: ${{ secrets.APP_PRIVATE_KEY }}
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'

# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
run 'forwarding a third name fails' 1 'forwards [' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      APP_PRIVATE_KEY: ${{ secrets.APP_PRIVATE_KEY }}'

# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
run 'forwarding fewer than the two names fails' 1 'forwards [' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}'

run 'a gate call with no secrets mapping fails' 1 'without an explicit' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: ./.github/workflows/llm-smoke.yaml'

# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
run 'a release with no call to the gate fails' 1 'has no job calling' \
	"$ok_smoke" \
	'jobs:
  other:
    uses: ./.github/workflows/connector-e2e.yaml
    secrets:
      GH_E2E_APP_PRIVATE_KEY: ${{ secrets.GH_E2E_APP_PRIVATE_KEY }}'

# A pinned ref on the uses: target must not defeat the match.
# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
run 'a pinned @ref on the gate call still matches' 1 'forwards [' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: cynative/cynative/.github/workflows/llm-smoke.yaml@main
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      APP_PRIVATE_KEY: ${{ secrets.APP_PRIVATE_KEY }}'

# A matching basename does not say whose workflow it is: a retarget at another owner
# would otherwise pass every arm while forwarding both keys out of the repo.
# shellcheck disable=SC2016 # fixtures must keep ${{ }} literal; do not expand here.
run 'a gate call retargeted at another owner fails' 1 'not this repository' \
	"$ok_smoke" \
	'jobs:
  llm-smoke:
    uses: attacker/collector/.github/workflows/llm-smoke.yaml@main
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}'

# Other reusable calls keep their own grants; only the gate call is constrained.
run 'other reusable calls are left alone' 0 '' \
	"$ok_smoke" \
	"$ok_release
  scoop-publish:
    uses: ./.github/workflows/scoop-publish.yaml
    secrets:
      APP_ID: \${{ secrets.APP_ID }}
      APP_PRIVATE_KEY: \${{ secrets.APP_PRIVATE_KEY }}"

# --- fail closed on anything unreadable --------------------------------------
# An unterminated ${{ is a workflow Actions rejects. Failing closed beats guessing
# where the expression ended: treating the remainder as the body used to mint a
# phantom secrets.NAME out of a shell comment that merely mentioned ${{.
run 'an unterminated expression fails closed' 1 'unterminated' \
	"$ok_smoke
        script: |
          # to interpolate a value, open it with \${{
          echo secrets.MY_KEY" \
	"$ok_release"

# Shared and self-referencing YAML nodes must not recurse forever or blow up
# exponentially; the walkers carry a visited set. A clean verdict, not a traceback.
run 'a self-referencing anchor still reports cleanly' 1 'secrets.* references are' \
	'self: &loop
  back: *loop' \
	"$ok_release"

printf 'jobs:\n  g:\n   bad\n  : [\n' >"$tmp/bad.yaml"
printf '%s\n' "$ok_release" >"$tmp/good-release.yaml"
printf 'name: \303\251\377\376 bad bytes\n' >"$tmp/binary.yaml"
ran=$((ran + 3))
run_raw 'unparseable YAML fails closed' 1 'not parseable YAML' "$tmp/bad.yaml" "$tmp/good-release.yaml"
run_raw 'a missing file fails closed' 1 'not readable' "$tmp/nope.yaml" "$tmp/good-release.yaml"
run_raw 'a non-UTF-8 file fails closed' 1 'not valid UTF-8' "$tmp/binary.yaml" "$tmp/good-release.yaml"

# Alias amplification: 13 nested levels of 4-way aliases is a few hundred bytes but
# expands to 4^13 logical nodes. Without the visited set the walk never finishes and
# burns the CI job's whole timeout, so pin that it terminates promptly.
{
	printf 'a0: &a0 [x, x, x, x]\n'
	level=1
	while [ "$level" -le 13 ]; do
		prev=$((level - 1))
		printf 'a%s: &a%s [*a%s, *a%s, *a%s, *a%s]\n' "$level" "$level" "$prev" "$prev" "$prev" "$prev"
		level=$((level + 1))
	done
} >"$tmp/bomb.yaml"
# The watchdog is python rather than the `timeout` binary, which a default macOS
# install lacks: a missing binary would exit 127 and, under an "anything but 124"
# check, be reported as a pass. The status is asserted exactly (1, the clean
# exact-set failure the bomb fixture produces) so a crash cannot read as success
# either.
ran=$((ran + 1))
set +e
python3 - "$script" "$tmp/bomb.yaml" "$tmp/good-release.yaml" <<'WATCHDOG'
import subprocess, sys

try:
    done = subprocess.run(
        [sys.executable, "-B", sys.argv[1], sys.argv[2], sys.argv[3]],
        capture_output=True, timeout=30, check=False,
    )
except subprocess.TimeoutExpired:
    sys.exit(124)
sys.exit(done.returncode)
WATCHDOG
bomb_rc=$?
set -e
if [ "$bomb_rc" -eq 124 ]; then
	printf 'FAIL alias amplification did not terminate within 30s\n' >&2
	fails=$((fails + 1))
elif [ "$bomb_rc" -ne 1 ]; then
	printf 'FAIL alias amplification exited %s, expected 1 (a clean fail-closed verdict)\n' "$bomb_rc" >&2
	fails=$((fails + 1))
else
	printf 'PASS alias amplification terminates\n'
fi

# The suite must never report success without having executed its cases (the
# fail-open shape this repo has been burned by before).
if [ "$ran" -lt 44 ]; then
	printf 'FAIL: only %s llm-smoke secret-reference cases ran, expected at least 44\n' "$ran" >&2
	exit 1
fi
if [ "$fails" -ne 0 ]; then
	printf 'FAIL: %s llm-smoke secret-reference unit test(s) failed\n' "$fails" >&2
	exit 1
fi
printf 'OK: llm-smoke secret-reference unit tests (%s cases)\n' "$ran"
