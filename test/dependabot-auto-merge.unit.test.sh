#!/bin/sh
# dependabot-auto-merge.unit.test.sh - offline unit tests for the "Resolve
# Dependabot PR" step of .github/workflows/dependabot-auto-merge.yaml, the gate
# that decides whether the App token is minted and auto-merge is armed.
#
# Hermetic: no network, no credentials. The step's `run:` block is extracted
# from the workflow and executed against a fake `gh` that serves canned API
# responses and applies the caller's --jq filter with the real jq, so the shell
# and the jq predicates under test are the ones the workflow runs. Requires jq.
# Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
workflow="$root/.github/workflows/dependabot-auto-merge.yaml"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

# The `run:` block of the Resolve step, dedented.
awk '
  /- name: Resolve Dependabot PR/ { in_step = 1; next }
  in_step && /^        run: \|$/ { in_run = 1; next }
  in_run && /^          / { sub(/^          /, ""); print; next }
  in_run { exit }
' "$workflow" > "$tmp/step.sh"
if [ ! -s "$tmp/step.sh" ]; then
  printf 'FAIL: could not extract the Resolve Dependabot PR step\n' >&2
  exit 1
fi

# Fake gh: `gh api <path> [--paginate] [--jq <filter>]`, answered from $FIX.
cat > "$tmp/bin/gh" <<'EOF_GH'
#!/bin/sh
path=""
filter=""
shift
while [ "$#" -gt 0 ]; do
  case "$1" in
    --jq) filter=$2; shift 2 ;;
    --paginate) shift ;;
    *) path=$1; shift ;;
  esac
done
case "$path" in
  */commits/*/pulls) file=$FIX/pulls.json ;;
  */pulls/*/commits) file=$FIX/commits.json ;;
  */pulls/*) file=$FIX/pr.json ;;
  *) echo "unexpected gh path: $path" >&2; exit 1 ;;
esac
jq -r "$filter" "$file"
EOF_GH
chmod +x "$tmp/bin/gh"

sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# dependabot commit: author dependabot[bot], committer web-flow, verified.
dep='{"sha":"1111111111111111","author":{"login":"dependabot[bot]"},"committer":{"login":"web-flow"},"commit":{"verification":{"verified":true}}}'

# run_case <name> <commits-json> <pr-commit-count> <pulls-json>; sets out and log.
run_case() {
  fix="$tmp/fix.$1"
  mkdir "$fix"
  printf '%s\n' "$4" > "$fix/pulls.json"
  printf '%s\n' "$2" > "$fix/commits.json"
  printf '{"commits":%s}\n' "$3" > "$fix/pr.json"
  : > "$fix/out"
  PATH="$tmp/bin:$PATH" FIX="$fix" GITHUB_OUTPUT="$fix/out" \
    GITHUB_REPOSITORY=cynative/cynative HEAD_SHA="$sha" GH_TOKEN=x \
    bash -c "$(cat "$tmp/step.sh")" > "$fix/log" 2>&1 || {
      fail "$1: step exited non-zero"
      cat "$fix/log" >&2
    }
  out=$(cat "$fix/out")
  log=$(cat "$fix/log")
}

# expect_out <description> <expected out>: compare the step's output file.
expect_out() {
  if [ "$out" = "$2" ]; then
    pass "$1"
  else
    fail "$1: out=[$out] log=[$log]"
  fi
}

open_pr="[{\"number\":7,\"state\":\"open\",\"base\":{\"ref\":\"main\"},\"user\":{\"login\":\"dependabot[bot]\"},\"head\":{\"sha\":\"$sha\"}}]"

run_case clean "[$dep]" 1 "$open_pr"
expect_out "pure Dependabot PR is armed" "number=7"

run_case two "[$dep,$dep]" 2 "$open_pr"
expect_out "several Dependabot commits are armed" "number=7"

human='{"sha":"2222222222222222","author":{"login":"someone"},"committer":{"login":"someone"},"commit":{"verification":{"verified":false}}}'
run_case mixed "[$dep,$human]" 2 "$open_pr"
expect_out "a pushed human commit is not armed" ""
case "$log" in *"2222222 author=someone committer=someone verified=false"*"not arming"*|*"not arming"*"2222222 author=someone"*) pass "the skip names the offending commit" ;; *) fail "skip log: [$log]" ;; esac

unverified='{"sha":"3333333333333333","author":{"login":"dependabot[bot]"},"committer":{"login":"web-flow"},"commit":{"verification":{"verified":false}}}'
run_case unverified "[$unverified]" 1 "$open_pr"
expect_out "an unverified Dependabot-looking commit is not armed" ""

selfsigned='{"sha":"4444444444444444","author":{"login":"dependabot[bot]"},"committer":{"login":"someone"},"commit":{"verification":{"verified":true}}}'
run_case committer "[$selfsigned]" 1 "$open_pr"
expect_out "a commit not committed by GitHub is not armed" ""

nologin='{"sha":"5555555555555555","author":null,"committer":{"login":"web-flow"},"commit":{"verification":{"verified":true}}}'
run_case nologin "[$nologin]" 1 "$open_pr"
expect_out "a commit with no linked author is not armed" ""

run_case truncated "[$dep]" 3 "$open_pr"
expect_out "an incomplete commit listing is not armed" ""
case "$log" in *"listed 1 of 3"*) pass "the skip reports the counts" ;; *) fail "count log: [$log]" ;; esac

run_case nopr "[$dep]" 1 '[]'
expect_out "no matching PR is not armed" ""
case "$log" in *"nothing to do"*) pass "no matching PR logs and stops" ;; *) fail "no PR log: [$log]" ;; esac

human_pr=$(printf '%s' "$open_pr" | sed 's/"dependabot\[bot\]"/"someone"/')
run_case humanpr "[$dep]" 1 "$human_pr"
expect_out "a human-authored PR is not armed" ""

if [ "$fails" -ne 0 ]; then
  printf '%s dependabot-auto-merge unit test(s) failed\n' "$fails" >&2
  exit 1
fi
printf 'OK: dependabot-auto-merge unit tests\n'
